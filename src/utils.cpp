#include "kaskad_users-configurator-gtk3/utils.hpp"
#include "tinyxml2/tinyxml2.h"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <glib.h>
#include <glibmm/ustring.h>
#include <gtkmm.h>
#include <iomanip>
#include <iostream>
#include <lber.h>
#include <ldap.h>
#include <openssl/evp.h>
#include <regex>
#include <thread>

std::vector<std::string> extract_cns(const std::string &dn_string) {
    std::vector<std::string> cn_list;
    std::regex cn_regex(R"(CN=([^,]+))", std::regex_constants::icase);
    auto words_begin =
        std::sregex_iterator(dn_string.begin(), dn_string.end(), cn_regex);
    auto words_end = std::sregex_iterator();

    for (std::sregex_iterator iter = words_begin; iter != words_end; ++iter) {
        cn_list.push_back((*iter)[1].str());
    }
    return cn_list;
}

std::string base_dn_to_upn(const std::string &base_dn,
                           const std::string &username) {
    std::string upn = username + "@";
    std::stringstream ss(base_dn);
    std::string token;
    std::vector<std::string> parts;

    while (std::getline(ss, token, ',')) {
        size_t pos = token.find("dc=");
        if (pos != std::string::npos) {
            std::string dc_val = token.substr(pos + 3);
            upn += dc_val + ".";
        }
    }
    return upn.substr(0, upn.size() - 1);
}

std::tuple<int, LDAP *> ldap_connect_and_bind(const std::string &ldap_uri,
                                              const std::string &bind_dn,
                                              const std::string &password) {
    LDAP *ld = nullptr;
    int rc = ldap_initialize(&ld, ldap_uri.c_str());
    if (rc != LDAP_SUCCESS) {
        return std::make_tuple(rc, nullptr);
    }

    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    void *referral = LDAP_OPT_OFF;
    ldap_set_option(ld, LDAP_OPT_REFERRALS, &referral);

    struct berval cred;
    cred.bv_val = const_cast<char *>(password.c_str());
    cred.bv_len = password.size();

    rc = ldap_sasl_bind_s(ld, bind_dn.c_str(), LDAP_SASL_SIMPLE, &cred, NULL,
                          NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, NULL, NULL);
        return std::make_tuple(rc, nullptr);
    }

    return std::make_tuple(0, ld);
}

int ldap_parse_objs(LDAP *ld, const std::string &base_dn,
                    const std::vector<std::string> &attrs,
                    std::vector<LdapParsedObj> &top_groups,
                    std::vector<LdapParsedObj> &sub_groups,
                    std::vector<LdapParsedObj> &users,
                    std::vector<std::string> &groups_cns) {
    std::vector<char *> attrs_array;
    for (const auto &attr : attrs) {
        attrs_array.push_back(const_cast<char *>(attr.c_str()));
    }
    attrs_array.push_back(nullptr);

    const int pageSize = 100;
    struct timeval timeout = {5, 0};
    struct berval *cookie = nullptr;

    // Парсинг групп
    do {
        LDAPControl *pageControl = nullptr;
        int rc =
            ldap_create_page_control(ld, pageSize, cookie, 0, &pageControl);
        if (rc != LDAP_SUCCESS) {
            if (cookie)
                ber_bvfree(cookie);
            return rc;
        }
        LDAPControl *serverControls[] = {pageControl, nullptr};
        LDAPMessage *result = nullptr;
        rc = ldap_search_ext_s(ld, base_dn.c_str(), LDAP_SCOPE_SUBTREE,
                               "(objectClass=group)", attrs_array.data(), 0,
                               serverControls, nullptr, &timeout, 0, &result);
        ldap_control_free(pageControl);
        if (rc != LDAP_SUCCESS && rc != LDAP_PARTIAL_RESULTS) {
            if (cookie)
                ber_bvfree(cookie);
            if (result)
                ldap_msgfree(result);
            return rc;
        }
        if (!result) {
            if (cookie)
                ber_bvfree(cookie);
            return rc;
        }

        LDAPMessage *entry = ldap_first_entry(ld, result);
        while (entry != nullptr) {
            LdapParsedObj group_obj;
            BerElement *ber = nullptr;
            char *attr_name = ldap_first_attribute(ld, entry, &ber);
            while (attr_name != nullptr) {
                struct berval **values =
                    ldap_get_values_len(ld, entry, attr_name);
                if (values != nullptr) {
                    for (int i = 0; values[i] != nullptr; ++i) {
                        std::string val(values[i]->bv_val, values[i]->bv_len);
                        if (strcmp(attr_name, "cn") == 0) {
                            group_obj.name = val;
                        } else if (strcmp(attr_name, "description") == 0) {
                            group_obj.description = val;
                        } else if (strcmp(attr_name, "memberOf") == 0) {
                            std::vector<std::string> member_of =
                                extract_cns(val);
                            group_obj.member_of.insert(
                                group_obj.member_of.end(), member_of.begin(),
                                member_of.end());
                        }
                    }
                    ldap_value_free_len(values);
                }
                ldap_memfree(attr_name);
                attr_name = ldap_next_attribute(ld, entry, ber);
            }
            if (ber)
                ber_free(ber, 0);
            if (!group_obj.name.empty()) {
                groups_cns.push_back(group_obj.name);
                if (group_obj.member_of.empty())
                    top_groups.push_back(std::move(group_obj));
                else
                    sub_groups.push_back(std::move(group_obj));
            }
            entry = ldap_next_entry(ld, entry);
        }

        LDAPControl **returnedControls = nullptr;
        rc = ldap_parse_result(ld, result, nullptr, nullptr, nullptr, nullptr,
                               &returnedControls, 0);
        if (rc != LDAP_SUCCESS) {
            if (cookie)
                ber_bvfree(cookie);
            ldap_msgfree(result);
            return rc;
        }
        struct berval *newCookie = nullptr;
        for (int i = 0; returnedControls && returnedControls[i] != nullptr;
             ++i) {
            if (strcmp(returnedControls[i]->ldctl_oid,
                       LDAP_CONTROL_PAGEDRESULTS) == 0) {
                newCookie = ber_bvdup(&returnedControls[i]->ldctl_value);
                break;
            }
        }
        ldap_controls_free(returnedControls);
        ldap_msgfree(result);
        if (cookie)
            ber_bvfree(cookie);
        cookie = newCookie;
    } while (cookie != nullptr && cookie->bv_len > 0);

    // Парсинг пользователей
    cookie = nullptr;
    do {
        LDAPControl *pageControl = nullptr;
        int rc =
            ldap_create_page_control(ld, pageSize, cookie, 0, &pageControl);
        if (rc != LDAP_SUCCESS) {
            if (cookie)
                ber_bvfree(cookie);
            return rc;
        }
        LDAPControl *serverControls[] = {pageControl, nullptr};
        LDAPMessage *result = nullptr;
        rc = ldap_search_ext_s(ld, base_dn.c_str(), LDAP_SCOPE_SUBTREE,
                               "(objectClass=user)", attrs_array.data(), 0,
                               serverControls, nullptr, &timeout, 0, &result);
        ldap_control_free(pageControl);
        if (rc != LDAP_SUCCESS && rc != LDAP_PARTIAL_RESULTS) {
            if (cookie)
                ber_bvfree(cookie);
            if (result)
                ldap_msgfree(result);
            return rc;
        }
        if (!result) {
            if (cookie)
                ber_bvfree(cookie);
            return rc;
        }

        LDAPMessage *entry = ldap_first_entry(ld, result);
        while (entry != nullptr) {
            LdapParsedObj user_obj;
            BerElement *ber = nullptr;
            char *attr_name = ldap_first_attribute(ld, entry, &ber);
            while (attr_name != nullptr) {
                struct berval **values =
                    ldap_get_values_len(ld, entry, attr_name);
                if (values != nullptr) {
                    for (int i = 0; values[i] != nullptr; ++i) {
                        std::string val(values[i]->bv_val, values[i]->bv_len);
                        Glib::ustring val_upper =
                            Glib::ustring(val).uppercase();
                        if (strcmp(attr_name, "cn") == 0) {
                            user_obj.username = val_upper;
                            user_obj.name = val;
                        } else if (strcmp(attr_name, "memberOf") == 0) {
                            std::vector<std::string> member_of =
                                extract_cns(val);
                            user_obj.member_of.insert(user_obj.member_of.end(),
                                                      member_of.begin(),
                                                      member_of.end());
                        }
                    }
                    ldap_value_free_len(values);
                }
                ldap_memfree(attr_name);
                attr_name = ldap_next_attribute(ld, entry, ber);
            }
            if (ber)
                ber_free(ber, 0);

            if (!user_obj.name.empty())
                users.push_back(std::move(user_obj));
            entry = ldap_next_entry(ld, entry);
        }

        LDAPControl **returnedControls = nullptr;
        rc = ldap_parse_result(ld, result, nullptr, nullptr, nullptr, nullptr,
                               &returnedControls, 0);
        if (rc != LDAP_SUCCESS) {
            if (cookie)
                ber_bvfree(cookie);
            ldap_msgfree(result);
            return rc;
        }
        struct berval *newCookie = nullptr;
        for (int i = 0; returnedControls && returnedControls[i] != nullptr;
             ++i) {
            if (strcmp(returnedControls[i]->ldctl_oid,
                       LDAP_CONTROL_PAGEDRESULTS) == 0) {
                newCookie = ber_bvdup(&returnedControls[i]->ldctl_value);
                break;
            }
        }
        ldap_controls_free(returnedControls);
        ldap_msgfree(result);
        if (cookie)
            ber_bvfree(cookie);
        cookie = newCookie;
    } while (cookie != nullptr && cookie->bv_len > 0);

    if (cookie)
        ber_bvfree(cookie);
    return 0;
}

void activedir_parse_async(
    Gtk::Window *parent_window, Gtk::MessageDialog *dialog,
    Gtk::ScrolledWindow *scrolled_activedir, Gtk::TreeView *treeview_activedir,
    const MainSettings &main_settings, const ObjCols &obj_cols,
    const Glib::RefPtr<Gdk::Pixbuf> &pixbuf_user,
    const Glib::RefPtr<Gdk::Pixbuf> &pixbuf_group,
    std::atomic<bool> &is_canceled, std::atomic<bool> &is_loaded) {

    Glib::RefPtr<Gtk::TreeStore> treestore_activedir =
        Gtk::TreeStore::create(obj_cols);
    Glib::signal_idle().connect_once([dialog, scrolled_activedir,
                                      treeview_activedir, treestore_activedir,
                                      &obj_cols, &is_canceled]() {
        if (is_canceled.load())
            return;
        Gtk::CellRendererPixbuf *renderer_icon =
            Gtk::make_managed<Gtk::CellRendererPixbuf>();
        Gtk::TreeViewColumn *col_icon_name =
            Gtk::make_managed<Gtk::TreeViewColumn>();
        col_icon_name->pack_start(*renderer_icon, false);
        col_icon_name->add_attribute(renderer_icon->property_pixbuf(),
                                     obj_cols.icon);
        col_icon_name->set_sizing(Gtk::TREE_VIEW_COLUMN_FIXED);
        Gtk::CellRendererText *renderer_name =
            Gtk::make_managed<Gtk::CellRendererText>();
        col_icon_name->pack_start(*renderer_name, false);
        col_icon_name->add_attribute(renderer_name->property_text(),
                                     obj_cols.name);
        treeview_activedir->append_column(*col_icon_name);
        treeview_activedir->set_model(treestore_activedir);
    });

    std::thread([parent_window, dialog, main_settings, &obj_cols, pixbuf_user,
                 pixbuf_group, treestore_activedir, scrolled_activedir,
                 treeview_activedir, &is_canceled, &is_loaded]() {
        if (is_canceled.load())
            return;
        auto [ret, ld] =
            ldap_connect_and_bind(main_settings.ldap_server_name,
                                  base_dn_to_upn(main_settings.ldap_base_dn,
                                                 main_settings.ldap_user_name),
                                  main_settings.ldap_user_password);
        if (!ld || is_canceled.load()) {
            if (ld)
                ldap_unbind_ext_s(ld, NULL, NULL);
            Glib::signal_idle().connect_once([parent_window, ret]() {
                Gtk::MessageDialog error_dialog(
                    *parent_window,
                    "Не удалось подключиться к LDAP-серверу:\n" +
                        std::string(ldap_err2string(ret)),
                    false, Gtk::MESSAGE_ERROR, Gtk::BUTTONS_OK);
                error_dialog.run();
            });
            return;
        }

        std::vector<LdapParsedObj> top_groups, sub_groups, users;
        std::vector<std::string> groups_cns;
        if (is_canceled.load()) {
            ldap_unbind_ext_s(ld, NULL, NULL);
            return;
        }
        ret = ldap_parse_objs(ld, main_settings.ldap_base_dn,
                              {"cn", "description", "memberOf"}, top_groups,
                              sub_groups, users, groups_cns);
        ldap_unbind_ext_s(ld, NULL, NULL);

        if (ret != 0 || is_canceled.load()) {
            Glib::signal_idle().connect_once([parent_window, ret]() {
                Gtk::MessageDialog error_dialog(
                    *parent_window,
                    "Ошибка парсинга LDAP:\n" +
                        std::string(ldap_err2string(ret)),
                    false, Gtk::MESSAGE_ERROR, Gtk::BUTTONS_OK);
                error_dialog.run();
            });
            return;
        }

        Glib::signal_idle().connect_once(
            [treestore_activedir, &obj_cols, top_groups = std::move(top_groups),
             sub_groups = std::move(sub_groups), users = std::move(users),
             groups_cns = std::move(groups_cns), pixbuf_group, pixbuf_user,
             dialog, scrolled_activedir, treeview_activedir, &is_canceled]() {
                if (is_canceled.load())
                    return;
                for (const auto &obj : top_groups) {
                    Gtk::TreeModel::Row new_row =
                        *(treestore_activedir->append());
                    new_row[obj_cols.icon] = pixbuf_group;
                    new_row[obj_cols.name] = obj.name;
                    new_row[obj_cols.extrainfo] = obj.description;
                }
                std::set<std::string> inserted_subgroups;
                bool inserted = true;
                while (inserted && !is_canceled.load()) {
                    inserted = false;
                    for (const auto &obj : sub_groups) {
                        if (inserted_subgroups.find(obj.name) !=
                            inserted_subgroups.end())
                            continue;
                        bool can_insert = false;
                        for (const std::string &parent_name : obj.member_of) {
                            if (std::find(groups_cns.begin(), groups_cns.end(),
                                          parent_name) != groups_cns.end()) {
                                can_insert = true;
                                break;
                            }
                        }
                        if (!can_insert)
                            continue;
                        for (const std::string &parent_name : obj.member_of) {
                            Gtk::TreeModel::Row parent_row =
                                *get_by_name(parent_name, treestore_activedir,
                                             obj_cols, false);
                            if (parent_row) {
                                Gtk::TreeModel::Row new_row =
                                    *(treestore_activedir->append(
                                        parent_row.children()));
                                new_row[obj_cols.icon] = pixbuf_group;
                                new_row[obj_cols.name] = obj.name;
                                new_row[obj_cols.extrainfo] = obj.description;
                                inserted_subgroups.insert(obj.name);
                                inserted = true;
                                break;
                            }
                        }
                    }
                }
                auto exists_in_group = [&treestore_activedir, &obj_cols](
                                           const std::string &group_name,
                                           const std::string &username) {
                    Gtk::TreeModel::Row group_row = *get_by_name(
                        group_name, treestore_activedir, obj_cols, false);
                    for (Gtk::TreeModel::Row row : group_row.children()) {
                        if (row[obj_cols.username] == username)
                            return true;
                    }
                    return false;
                };
                for (const auto &obj : users) {
                    if (obj.username.empty() || is_canceled.load())
                        continue;
                    for (const auto &group_name : obj.member_of) {
                        Gtk::TreeModel::iterator group_iter = get_by_name(
                            group_name, treestore_activedir, obj_cols, false);
                        if (group_iter &&
                            !exists_in_group(group_name, obj.username)) {
                            Gtk::TreeModel::Row new_row =
                                *(treestore_activedir->append(
                                    group_iter->children()));
                            new_row[obj_cols.icon] = pixbuf_user;
                            new_row[obj_cols.username] = obj.username;
                            new_row[obj_cols.name] = obj.name;
                            new_row[obj_cols.extrainfo] = obj.description;
                        }
                    }
                }

                dialog->set_size_request(600, 800);
                treeview_activedir->queue_draw();
                if (!treestore_activedir->children().empty()) {
                    treeview_activedir->get_selection()->select(
                        treestore_activedir->children().begin());
                }
                Gtk::Frame *frame_activedir = Gtk::make_managed<Gtk::Frame>();
                scrolled_activedir->set_name("white_background");
                scrolled_activedir->set_policy(Gtk::POLICY_AUTOMATIC,
                                               Gtk::POLICY_AUTOMATIC);
                scrolled_activedir->add(*frame_activedir);
                frame_activedir->add(*treeview_activedir);
                treeview_activedir->set_vexpand(true);
                treeview_activedir->set_hexpand(true);
                scrolled_activedir->set_vexpand(true);
                scrolled_activedir->set_hexpand(true);
                frame_activedir->set_vexpand(true);
                frame_activedir->set_hexpand(true);
                treeview_activedir->set_headers_visible(false);
                scrolled_activedir->show_all();
                set_margin(*frame_activedir, 10, 10);
            });

        is_loaded.store(true);
    }).detach();
}

CellRendererThreeState::CellRendererThreeState(int initial_column_idx)
    : Gtk::CellRenderer() {
    property_mode() = static_cast<Gtk::CellRendererMode>(
        1); // Gtk::CellRendererMode::ACTIVATABLE
    threestate_col_idx_ = initial_column_idx;
}
CellRendererThreeState::type_signal_toggled
CellRendererThreeState::signal_toggled() {
    return signal_toggled_;
}
void CellRendererThreeState::render_vfunc(
    const Cairo::RefPtr<Cairo::Context> &cr, Gtk::Widget &widget,
    const Gdk::Rectangle &background_area, const Gdk::Rectangle &cell_area,
    Gtk::CellRendererState flags) {
    (void)widget;
    (void)background_area;
    (void)flags;
    int x = cell_area.get_x() + (cell_area.get_width() - 16) / 2;
    int y = cell_area.get_y() + (cell_area.get_height() - 16) / 2;
    float radius = 3.0;
    float stroke_width = 0.5;
    float inner_offset = 1;
    float inner_size = 16.0 - 2 * inner_offset;

    auto rounded_rectangle = [&](float x, float y, float w, float h, float r) {
        cr->begin_new_sub_path();
        cr->arc(x + w - r, y + r, r, -M_PI / 2, 0);
        cr->arc(x + w - r, y + h - r, r, 0, M_PI / 2);
        cr->arc(x + r, y + h - r, r, M_PI / 2, M_PI);
        cr->arc(x + r, y + r, r, M_PI, 3 * M_PI / 2);
        cr->close_path();
    };

    cr->set_source_rgb(1.0, 1.0, 1.0);
    cr->set_line_width(stroke_width);
    rounded_rectangle(x + 0.5, y + 0.5, 16 - 1, 16 - 1, radius);
    cr->fill_preserve();
    cr->set_source_rgb(0.74, 0.71, 0.69);
    cr->stroke();
    switch (threestate_) {
    case 1:
        cr->set_source_rgb(0.2, 0.52, 0.89);
        rounded_rectangle(x + inner_offset, y + inner_offset, inner_size,
                          inner_size, radius);
        cr->fill_preserve();
        cr->stroke();

        cr->set_source_rgb(1.0, 1.0, 1.0);
        cr->set_line_width(3.0);
        cr->move_to(x + 4, y + 6);
        cr->line_to(x + 7, y + 10.5);
        cr->line_to(x + 14, y + 5.3);
        cr->stroke();
        break;
    case 2:
        cr->set_source_rgb(0.89, 0.52, 0.2);
        rounded_rectangle(x + inner_offset, y + inner_offset, inner_size,
                          inner_size, radius);
        cr->fill_preserve();
        cr->stroke();

        cr->set_source_rgb(1.0, 1.0, 1.0);
        cr->set_line_width(3.0);
        cr->move_to(x + 3, y + 3);
        cr->line_to(x + 16 - 3, y + 16 - 3);
        cr->stroke();
        cr->move_to(x + 16 - 3, y + 3);
        cr->line_to(x + 3, y + 16 - 3);
        cr->stroke();
        break;
    }
}
bool CellRendererThreeState::activate_vfunc(
    GdkEvent *event, Gtk::Widget &widget, const Glib::ustring &path,
    const Gdk::Rectangle &background_area, const Gdk::Rectangle &cell_area,
    Gtk::CellRendererState flags) {
    (void)event;
    (void)widget;
    (void)background_area;
    (void)cell_area;
    (void)flags;
    signal_toggled().emit(path);
    return true;
}

CellRendererThreeStateGroup::CellRendererThreeStateGroup(int initial_column_idx)
    : Gtk::CellRenderer() {
    property_mode() = static_cast<Gtk::CellRendererMode>(
        1); // Gtk::CellRendererMode::ACTIVATABLE
    threestate_col_idx_ = initial_column_idx;
}
CellRendererThreeStateGroup::type_signal_toggled
CellRendererThreeStateGroup::signal_toggled() {
    return signal_toggled_;
}
void CellRendererThreeStateGroup::render_vfunc(
    const Cairo::RefPtr<Cairo::Context> &cr, Gtk::Widget &widget,
    const Gdk::Rectangle &background_area, const Gdk::Rectangle &cell_area,
    Gtk::CellRendererState flags) {
    (void)widget;
    (void)background_area;
    (void)flags;
    int x = cell_area.get_x() + (cell_area.get_width() - 16) / 2;
    int y = cell_area.get_y() + (cell_area.get_height() - 16) / 2;
    float radius = 3.0;
    float stroke_width = 0.5;
    float inner_offset = 1;
    float inner_size = 16.0 - 2 * inner_offset;

    auto rounded_rectangle = [&](float x, float y, float w, float h, float r) {
        cr->begin_new_sub_path();
        cr->arc(x + w - r, y + r, r, -M_PI / 2, 0);
        cr->arc(x + w - r, y + h - r, r, 0, M_PI / 2);
        cr->arc(x + r, y + h - r, r, M_PI / 2, M_PI);
        cr->arc(x + r, y + r, r, M_PI, 3 * M_PI / 2);
        cr->close_path();
    };

    cr->set_source_rgb(1.0, 1.0, 1.0);
    cr->set_line_width(stroke_width);
    rounded_rectangle(x + 0.5, y + 0.5, 16 - 1, 16 - 1, radius);
    cr->fill_preserve();
    cr->set_source_rgb(0.74, 0.71, 0.69);
    cr->stroke();
    switch (threestate_) {
    case 1:
        cr->set_source_rgb(0.2, 0.52, 0.89);
        rounded_rectangle(x + inner_offset, y + inner_offset, inner_size,
                          inner_size, radius);
        cr->fill_preserve();
        cr->stroke();

        cr->set_source_rgb(0.76, 0.85, 0.97);
        cr->set_line_width(3.0);
        cr->move_to(x + 4, y + 6);
        cr->line_to(x + 7, y + 10.5);
        cr->line_to(x + 14, y + 5.3);
        cr->stroke();
        break;
    case 2:
        cr->set_source_rgb(0.89, 0.52, 0.2);
        rounded_rectangle(x + inner_offset, y + inner_offset, inner_size,
                          inner_size, radius);
        cr->fill_preserve();
        cr->stroke();

        cr->set_source_rgb(0.74, 0.71, 0.69);
        cr->set_line_width(3.0);
        cr->move_to(x + 3, y + 3);
        cr->line_to(x + 16 - 3, y + 16 - 3);
        cr->stroke();
        cr->move_to(x + 16 - 3, y + 3);
        cr->line_to(x + 3, y + 16 - 3);
        cr->stroke();
        break;
    }
}
bool CellRendererThreeStateGroup::activate_vfunc(
    GdkEvent *event, Gtk::Widget &widget, const Glib::ustring &path,
    const Gdk::Rectangle &background_area, const Gdk::Rectangle &cell_area,
    Gtk::CellRendererState flags) {
    (void)event;
    (void)widget;
    (void)path;
    (void)background_area;
    (void)cell_area;
    (void)flags;
    signal_toggled().emit(path);
    return true;
}

template <typename T>
tinyxml2::XMLElement *
append_tree_val_element_template(tinyxml2::XMLDocument &doc,
                                 tinyxml2::XMLElement *parent, const char *name,
                                 const T &value) {
    tinyxml2::XMLElement *node = doc.NewElement(name);
    if constexpr (std::is_same_v<T, Glib::ustring> ||
                  std::is_same_v<T, std::string>) {
        node->SetText(value.c_str());
    } else if constexpr (std::is_integral_v<T>) {
        node->SetText(static_cast<int64_t>(value));
    } else if constexpr (std::is_floating_point_v<T>) {
        node->SetText(value);
    } else if constexpr (std::is_same_v<T, bool>) {
        node->SetText(value);
    } else {
        node->SetText(Glib::ustring::format(value).c_str());
    }

    parent->InsertEndChild(node);
    return node;
}

int cp1251_to_utf8(char *out, const char *in, int buflen) {
    static const int table[128] = {
        0x82D0,   0x83D0,   0x9A80E2, 0x93D1,   0x9E80E2, 0xA680E2, 0xA080E2,
        0xA180E2, 0xAC82E2, 0xB080E2, 0x89D0,   0xB980E2, 0x8AD0,   0x8CD0,
        0x8BD0,   0x8FD0,   0x92D1,   0x9880E2, 0x9980E2, 0x9C80E2, 0x9D80E2,
        0xA280E2, 0x9380E2, 0x9480E2, 0,        0xA284E2, 0x99D1,   0xBA80E2,
        0x9AD1,   0x9CD1,   0x9BD1,   0x9FD1,   0xA0C2,   0x8ED0,   0x9ED1,
        0x88D0,   0xA4C2,   0x90D2,   0xA6C2,   0xA7C2,   0x81D0,   0xA9C2,
        0x84D0,   0xABC2,   0xACC2,   0xADC2,   0xAEC2,   0x87D0,   0xB0C2,
        0xB1C2,   0x86D0,   0x96D1,   0x91D2,   0xB5C2,   0xB6C2,   0xB7C2,
        0x91D1,   0x9684E2, 0x94D1,   0xBBC2,   0x98D1,   0x85D0,   0x95D1,
        0x97D1,   0x90D0,   0x91D0,   0x92D0,   0x93D0,   0x94D0,   0x95D0,
        0x96D0,   0x97D0,   0x98D0,   0x99D0,   0x9AD0,   0x9BD0,   0x9CD0,
        0x9DD0,   0x9ED0,   0x9FD0,   0xA0D0,   0xA1D0,   0xA2D0,   0xA3D0,
        0xA4D0,   0xA5D0,   0xA6D0,   0xA7D0,   0xA8D0,   0xA9D0,   0xAAD0,
        0xABD0,   0xACD0,   0xADD0,   0xAED0,   0xAFD0,   0xB0D0,   0xB1D0,
        0xB2D0,   0xB3D0,   0xB4D0,   0xB5D0,   0xB6D0,   0xB7D0,   0xB8D0,
        0xB9D0,   0xBAD0,   0xBBD0,   0xBCD0,   0xBDD0,   0xBED0,   0xBFD0,
        0x80D1,   0x81D1,   0x82D1,   0x83D1,   0x84D1,   0x85D1,   0x86D1,
        0x87D1,   0x88D1,   0x89D1,   0x8AD1,   0x8BD1,   0x8CD1,   0x8DD1,
        0x8ED1,   0x8FD1};

    char *pout = out;
    for (; *in && ((out - pout) < buflen - 1);) {
        if (*in & 0x80) {
            int v = table[(int)(0x7f & *in++)];
            if (!v)
                continue;
            *out++ = (char)v;
            *out++ = (char)(v >> 8);
            if (v >>= 16)
                *out++ = (char)v;
        } else {
            *out++ = *in++;
        }
    }
    *out = 0;
    return (out - pout);
}

void cp1251_to_utf8(const std::string &s, std::string &out) {
    out.resize(s.length() * 2);

    int sz = cp1251_to_utf8(out.data(), s.c_str(), out.length());

    out.resize(sz);
}

std::string cp1251_to_utf8(const std::string &s) {
    std::string out;
    cp1251_to_utf8(s, out);
    return out;
}

std::string md5_hash(const std::string &pass, const std::string &username) {
    std::string input = pass + username;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to compute MD5 hash");
    }
    EVP_MD_CTX_free(ctx);
    std::stringstream ss;
    for (unsigned int i = 0; i < digest_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return ss.str();
}

Glib::DateTime parse_datetime(const Glib::ustring &dt_str) {
    struct tm tm = {};
    if (strptime(dt_str.c_str(), "%d.%m.%Y %H:%M", &tm) == nullptr) {
        return Glib::DateTime();
    }
    time_t time_epoch = mktime(&tm);
    if (time_epoch == -1) {
        return Glib::DateTime();
    }
    GDateTime *gdate =
        g_date_time_new_from_unix_local(static_cast<gint64>(time_epoch));
    return Glib::wrap(gdate);
}

Glib::ustring datetime_to_str(const Glib::DateTime &dt) {
    return dt.format("%d.%m.%Y %H:%M");
}

Glib::ustring format_datetime(const Glib::DateTime &dt) {
    static const std::vector<Glib::ustring> days = {
        "понедельник", "вторник", "среда",      "четверг",
        "пятница",     "суббота", "воскресенье"};
    static const std::vector<Glib::ustring> months = {
        "Январь", "Февраль", "Март",     "Апрель",  "Май",    "Июнь",
        "Июль",   "Август",  "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"};
    int day_of_week_idx = dt.get_day_of_week() - 1;
    int day = dt.get_day_of_month();
    int month_idx = dt.get_month() - 1;
    int year = dt.get_year();
    int hour = dt.get_hour();
    int minute = dt.get_minute();

    Glib::ustring minute_str =
        (minute < 10) ? ("0" + Glib::ustring(std::to_string(minute)))
                      : Glib::ustring(std::to_string(minute));
    return Glib::ustring::compose("%1, %2 %3 %4 г. в %5:%6",
                                  days[day_of_week_idx], day, months[month_idx],
                                  year, hour, minute_str);
}

bool is_all_spaces(const std::string &str) {
    return std::all_of(str.begin(), str.end(),
                       [](unsigned char c) { return std::isspace(c); });
}

Gtk::TreeModel::iterator
get_by_name_recursive(const std::string &name,
                      const Glib::RefPtr<Gtk::TreeStore> &treestore_objs,
                      const ObjCols &obj_cols, bool search_for_user,
                      Gtk::TreeModel::Children children) {
    Glib::ustring search_upper = Glib::ustring(name).uppercase();

    for (auto iter = children.begin(); iter != children.end(); ++iter) {
        Gtk::TreeModel::Row row = *iter;

        if (search_for_user) {
            Glib::ustring username =
                Glib::ustring(row[obj_cols.username]).uppercase();
            if (!username.empty() && username == search_upper)
                return iter;
        } else {
            Glib::ustring groupname =
                Glib::ustring(row[obj_cols.name]).uppercase();
            if (!groupname.empty() && groupname == search_upper)
                return iter;
        }
        if (iter->children()) {
            Gtk::TreeModel::iterator found =
                get_by_name_recursive(name, treestore_objs, obj_cols,
                                      search_for_user, iter->children());
            if (found)
                return found;
        }
    }
    return Gtk::TreeModel::iterator();
}
// Проверка наличия пользователя или группы
Gtk::TreeModel::iterator
get_by_name(const std::string &name,
            const Glib::RefPtr<Gtk::TreeStore> &treestore_objs,
            const ObjCols &obj_cols, bool search_for_user) {
    return get_by_name_recursive(name, treestore_objs, obj_cols,
                                 search_for_user, treestore_objs->children());
}

// false - полностью прозрачная, отсутсвующая или невалидная иконка
bool set_hexcoded_icon(Glib::RefPtr<Gdk::Pixbuf> &pixbuf,
                       const std::string &icohex) {
    if (icohex.empty())
        return false;
    std::vector<unsigned char> bytes;
    bytes.reserve(icohex.size() / 2);
    for (size_t i = 0; i < icohex.length(); i += 2) {
        std::string byte_string = icohex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(
            strtol(byte_string.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }

    try {
        auto stream = Gio::MemoryInputStream::create();
        stream->add_data(bytes.data(), bytes.size());
        pixbuf = Gdk::Pixbuf::create_from_stream(stream);

        // Проверка на полностью прозрачую иконку (Для поддержки старых версий
        // bmp в ico)
        if (!pixbuf->get_has_alpha())
            return true;
        int width = pixbuf->get_width();
        int height = pixbuf->get_height();
        int rowstride = pixbuf->get_rowstride();
        int n_channels = pixbuf->get_n_channels();
        guchar *pixels = pixbuf->get_pixels();
        for (int y = 0; y < height; ++y) {
            guchar *p = pixels + y * rowstride;
            for (int x = 0; x < width; ++x) {
                guchar alpha = p[x * n_channels + (n_channels - 1)];
                if (alpha != 0)
                    return true;
            }
        }
        return false;
    } catch (const Gdk::PixbufError &e) {
        pixbuf = Glib::RefPtr<Gdk::Pixbuf>();
        return false;
    }
}

void set_margin(Gtk::Widget &widget, int margin_horizontal,
                int margin_vertical) {
    widget.set_margin_top(margin_vertical);
    widget.set_margin_left(margin_horizontal);
    widget.set_margin_right(margin_horizontal);
    widget.set_margin_bottom(margin_vertical);
};

bool check_password(const std::string &username,
                    const std::string &entered_password,
                    const std::string &hashed_password) {
    std::string hash = md5_hash(entered_password, username);
    return hash == hashed_password;
}

void change_app_enabled(const std::string app_name,
                        std::vector<std::string> &apps_names, bool curr_val,
                        std::vector<bool> &apps_enabled,
                        std::vector<unsigned char> &apps_permissions) {
    int app_idx = 0;
    for (auto i = apps_names.begin(); i != apps_names.end(); ++i, ++app_idx) {
        if (*i == app_name) {
            apps_enabled[app_idx] = curr_val;
            return;
        }
    }
    apps_names.push_back(app_name);
    apps_enabled.push_back(curr_val);
    apps_permissions.insert(apps_permissions.end(), 25, 0);
}

void change_app_permission(const std::string &app_name,
                           std::vector<std::string> &apps_names, int action_idx,
                           unsigned char action_state,
                           std::vector<unsigned char> &apps_permissions) {
    int app_idx = 0;
    for (auto i = apps_names.begin(); i != apps_names.end(); ++i, ++app_idx) {
        if (*i == app_name) {
            apps_permissions[25 * app_idx + action_idx] = action_state;
            return;
        }
    }
}

std::vector<unsigned char>
get_app_permissions(const std::string &app_name,
                    const std::vector<std::string> &app_names,
                    const std::vector<unsigned char> &apps_permissions) {
    for (std::size_t app_idx = 0; app_idx < app_names.size(); ++app_idx) {
        if (app_names[app_idx] == app_name) {
            auto start_iter = apps_permissions.begin() + 25 * app_idx;
            auto end_iter = start_iter + 25;
            return std::vector<unsigned char>(start_iter, end_iter);
        }
    }
    return std::vector<unsigned char>(25, 0);
}

void change_zone_permission(const std::string &zone_name,
                            std::vector<std::string> &zones_names,
                            unsigned char zone_state,
                            std::vector<unsigned char> &zones_permissions) {
    int zone_idx = 0;
    for (auto i = zones_names.begin(); i != zones_names.end(); ++i) {
        if (*i == zone_name) {
            zones_permissions[zone_idx] = zone_state;
            return;
        } else {
            zone_idx++;
        }
    }
    zones_names.push_back(zone_name);
    zones_permissions.push_back(zone_state);
}

unsigned char
get_zone_permissions(const std::string &zone_name,
                     const std::vector<std::string> &zones_names,
                     const std::vector<unsigned char> &zones_permissions) {
    for (std::size_t zone_idx = 0; zone_idx < zones_names.size(); ++zone_idx) {
        if (zones_names[zone_idx] == zone_name) {
            return zones_permissions[zone_idx];
        }
    }
    return 0;
}

int GetChildInt(tinyxml2::XMLElement *parent, const char *child_name) {
    if (!parent)
        return 0;
    tinyxml2::XMLElement *child = parent->FirstChildElement(child_name);
    if (!child)
        return 0;
    const char *text = child->GetText();
    if (!text)
        return 0;
    return std::stoi(text);
}

Glib::ustring GetChildText(tinyxml2::XMLElement *parent,
                           const char *child_name) {
    if (!parent)
        return "";
    tinyxml2::XMLElement *child = parent->FirstChildElement(child_name);
    if (!child)
        return "";
    const char *text = child->GetText();
    if (!text)
        return "";
    return Glib::ustring(text);
}

Glib::ustring GetLastChildText(tinyxml2::XMLElement *parent,
                               const char *child_name) {
    if (!parent)
        return "";
    tinyxml2::XMLElement *second_child = parent->LastChildElement(child_name);
    if (!second_child)
        return "";
    const char *text = second_child->GetText();
    if (!text)
        return "";
    return Glib::ustring(text);
}

std::string parse_userlist_config(const std::string &config_path,
                                  MainSettings &main_settings,
                                  std::string &errors) {
    try {
        Glib::KeyFile key_file;
        key_file.load_from_file(config_path);
        Glib::ustring db_file_name =
            key_file.get_string("UserList", "DBFileName");

        main_settings.type_login =
            key_file.get_integer("UserList", "TypeLogin");
        Glib::ustring style = key_file.get_string("UserList", "Style");
        main_settings.style = style;
        main_settings.synch_db_users =
            key_file.get_boolean("UserList", "Synch_DBUsers");

        main_settings.keyboard_visible =
            key_file.get_boolean("KeyboardDisplay", "Visible");
        main_settings.keyboard_button_size =
            key_file.get_integer("KeyboardDisplay", "BtnSize");
        main_settings.keyboard_button_font_size =
            key_file.get_integer("KeyboardDisplay", "BtnFontSize");
        main_settings.keyboard_button_font_bold =
            key_file.get_boolean("KeyboardDisplay", "BtnFontBold");
        main_settings.keyboard_button_font_italic =
            key_file.get_boolean("KeyboardDisplay", "BtnFontItalic");
        main_settings.keyboard_button_font_underline =
            key_file.get_boolean("KeyboardDisplay", "BtnFontUnderline");
        main_settings.keyboard_button_font_strikeout =
            key_file.get_boolean("KeyboardDisplay", "BtnFontStrikeOut");

        return db_file_name;
    } catch (const Glib::FileError &e) {
        errors +=
            "- Не удалось загрузить файл конфигурации: " + e.what() + "\n";
    } catch (const Glib::KeyFileError &e) {
        if (e.code() == Glib::KeyFileError::KEY_NOT_FOUND) {
            return "";
        } else
            errors +=
                "- Ошибка парсинга файла конфигурации: " + e.what() + "\n";
    }
    return "";
}

bool parse_ldap_config(const std::string &config_path,
                       MainSettings &main_settings, std::string &errors) {
    try {
        Glib::KeyFile key_file;
        key_file.load_from_file(config_path);
        Glib::ustring server_name = key_file.get_string("Config", "ServerName");
        Glib::ustring base_dn = key_file.get_string("Config", "BaseDN");
        Glib::ustring user_name = key_file.get_string("Config", "UserName");
        Glib::ustring password = key_file.get_string("Config", "Password");
        Glib::ustring admin_group = key_file.get_string("Config", "AdminGroup");

        main_settings.ldap_server_name = server_name;
        main_settings.ldap_base_dn = base_dn;
        main_settings.ldap_user_name = user_name;
        main_settings.ldap_user_password = password;
        main_settings.ldap_admin_group = admin_group;
        return true;
    } catch (const Glib::FileError &e) {
        errors +=
            "- Не удалось загрузить файл конфигурации: " + e.what() + "\n";
    } catch (const Glib::KeyFileError &e) {
        errors = "- Ошибка парсинга файла конфигурации: " + e.what() + "\n";
    }
    return false;
}

// Парсинг файла конфигурации users.xml
bool parse_users_config(const std::string &config_path,
                        Glib::RefPtr<Gtk::TreeStore> treestore_objs,
                        const ObjCols &obj_cols,
                        Glib::RefPtr<Gtk::ListStore> liststore_actions_apps,
                        Glib::RefPtr<Gtk::ListStore> liststore_actions_private,
                        const ActionCols &action_cols,
                        Glib::RefPtr<Gtk::TreeStore> treestore_zones,
                        const ZoneCols &zone_cols, std::string &errors) {
    std::ifstream f(config_path, std::ios::binary);
    std::error_code ec;
    if (std::filesystem::is_directory(config_path)) {
        errors += "- Путь базы данных пользователей в UserList.ini "
                  "является директорией: " +
                  config_path;
        return false;
    }
    if (!f.is_open()) {
        (void)std::filesystem::status(config_path, ec);
        if (ec) {
            errors +=
                "- Не удалось открыть файл конфигурации: " + ec.message() +
                "\n ";
            return false;
        }
    }
    std::string utf8_data;
    std::vector<char> buffer((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
    std::string raw_data(buffer.data(), buffer.size());
    if (g_utf8_validate(raw_data.c_str(), static_cast<gssize>(raw_data.size()),
                        nullptr)) {
        utf8_data = raw_data;
    } else {
        utf8_data = cp1251_to_utf8(raw_data);
    }
    tinyxml2::XMLDocument config;
    try {
        tinyxml2::XMLError result =
            config.Parse(utf8_data.c_str(), utf8_data.size());
        if (result != tinyxml2::XML_SUCCESS) {
            errors += std::string("- Не удалось прочитать файл конфигурации ") +
                      config.ErrorStr() + "\n";
            return false;
        }
    } catch (const Glib::Error &e) {
        errors += "- Не удалось прочитать файл конфигурации " + e.what() + "\n";
        return false;
    }
    tinyxml2::XMLElement *root = config.FirstChildElement("KSheriff_Cfg");
    std::map<Glib::ustring, Gtk::TreePath> group_paths;

    auto set_app_permissions =
        [](const std::string &app_name, std::vector<std::string> &apps_names,
           std::vector<bool> &apps_enabled, const std::string &permissions_str,
           std::vector<unsigned char> &apps_permissions) {
            std::vector<unsigned char> app_permissions;
            std::string permissions_str_copy = permissions_str;
            permissions_str_copy.insert(permissions_str_copy.end(),
                                        50 - permissions_str_copy.size(), '0');
            for (std::size_t i = 0; i + 1 < permissions_str_copy.size();
                 i += 2) {
                std::string byte_str = permissions_str_copy.substr(i, 2);
                unsigned char byte = static_cast<unsigned char>(
                    std::stoi(byte_str, nullptr, 16));
                app_permissions.push_back(byte);
            }

            apps_names.push_back(app_name);
            apps_enabled.push_back(true);
            apps_permissions.insert(apps_permissions.end(),
                                    app_permissions.begin(),
                                    app_permissions.end());
        };
    auto set_zone_permission =
        [&treestore_zones,
         &zone_cols](int station_id, std::vector<std::string> &zones_names,
                     unsigned char zone_permission,
                     std::vector<unsigned char> &zones_permissions) {
            for (auto &top_child_row : treestore_zones->children()) {
                Glib::ustring top_child_zone_name =
                    top_child_row[zone_cols.zonename];
                int top_child_station_id = top_child_row[zone_cols.station_id];
                if (top_child_station_id == station_id) {
                    zones_names.push_back(top_child_zone_name);
                    zones_permissions.push_back(zone_permission);
                    break;
                }
            }
        };

    for (tinyxml2::XMLElement *table = root->FirstChildElement("Table");
         table != nullptr; table = table->NextSiblingElement("Table")) {
        const char *name = table->FirstChildElement("Name")->GetText();

        // Парсинг групп
        if (strcmp(name, "GROUPLIST") == 0) {
            tinyxml2::XMLElement *records = table->FirstChildElement("Records");
            if (!records)
                continue;
            for (tinyxml2::XMLElement *record =
                     records->FirstChildElement("Record");
                 record != nullptr;
                 record = record->NextSiblingElement("Record")) {
                Glib::ustring grpname = GetChildText(record, "GRPNAME");
                Gtk::TreeModel::iterator iter = treestore_objs->append();
                Gtk::TreeModel::Row row = *iter;

                row[obj_cols.name] = grpname;
                row[obj_cols.flags] = GetChildInt(record, "FLAGS");
                row[obj_cols.allowtime] = GetChildText(record, "ALLOWTIME");
                row[obj_cols.pwdkeepperiod] =
                    GetChildInt(record, "PWDKEEPPERIOD");
                row[obj_cols.extrainfo] = GetChildText(record, "DESCRIPTION");
                row[obj_cols.stations] = GetChildText(record, "STATIONS");
                row[obj_cols.droptimeout] = GetChildInt(record, "DROPTIMEOUT");
                row[obj_cols.psprdaccess] = GetChildText(record, "PSPRDACCESS");
                row[obj_cols.pspwraccess] = GetChildText(record, "PSPWRACCESS");
                row[obj_cols.psprdaccess_] =
                    GetChildText(record, "PSPRDACCESS_");
                row[obj_cols.pspwraccess_] =
                    GetChildText(record, "PSPWRACCESS_");
                row[obj_cols.priority_write] =
                    static_cast<int>(GetChildInt(record, "PRIORITY_WRITE"));
                row[obj_cols.typeobject] = GetChildInt(record, "TYPEGROUP");
                row[obj_cols.sid] = GetChildText(record, "SID");

                Gtk::TreePath path = treestore_objs->get_path(iter);
                group_paths[grpname] = path;
            }
        }

        // Парсинг приложений
        if (strcmp(name, "APPLIST") == 0) {
            tinyxml2::XMLElement *records = table->FirstChildElement("Records");
            if (!records)
                continue;
            for (tinyxml2::XMLElement *record =
                     records->FirstChildElement("Record");
                 record != nullptr;
                 record = record->NextSiblingElement("Record")) {
                Gtk::TreeModel::iterator iter =
                    liststore_actions_apps->append();
                Gtk::TreeModel::Row row = *iter;
                Glib::ustring appname = GetChildText(record, "APPNAME");
                row[action_cols.appname] = appname;
                row[action_cols.description] =
                    GetChildText(record, "DESCRIPTION");
                row[action_cols.globactmask] =
                    GetLastChildText(record, "GLOBACTMASK");
                std::string icohex = GetChildText(record, "ICO");
                Glib::RefPtr<Gdk::Pixbuf> pixbuf;
                bool is_not_fully_transparent =
                    set_hexcoded_icon(pixbuf, icohex);
                if (is_not_fully_transparent) {
                    row[action_cols.icon] = pixbuf;
                    continue;
                }
                std::string def_icohex;
                for (const auto &i : DEFAULT_APPS) {
                    if (std::get<0>(i) == name) {
                        def_icohex = std::get<2>(i);
                        break;
                    }
                }
                if (!def_icohex.empty()) {
                    (void)set_hexcoded_icon(pixbuf, def_icohex);
                    row[action_cols.icon] = pixbuf;
                }
            }
        }

        // Парсинг действий
        if (strcmp(name, "ACTIONS") == 0) {
            tinyxml2::XMLElement *records = table->FirstChildElement("Records");
            if (!records)
                continue;
            for (tinyxml2::XMLElement *record =
                     records->FirstChildElement("Record");
                 record != nullptr;
                 record = record->NextSiblingElement("Record")) {
                Gtk::TreeModel::Row row = *liststore_actions_private->append();
                Glib::ustring actionname = GetChildText(record, "ACTIONNAME");
                row[action_cols.is_visible] = false;
                row[action_cols.is_threestate] = 0;
                row[action_cols.action_id] = GetChildInt(record, "ACTIONID");
                row[action_cols.appname] = GetChildText(record, "APPNAME");
                row[action_cols.actionname] = actionname;
                row[action_cols.description] =
                    GetChildText(record, "DESCRIPTION");
                std::string icohex = GetChildText(record, "ICO");
                Glib::RefPtr<Gdk::Pixbuf> pixbuf;
                bool is_not_fully_transparent =
                    set_hexcoded_icon(pixbuf, icohex);
                if (is_not_fully_transparent) {
                    row[action_cols.icon] = pixbuf;
                    continue;
                }
                std::string def_icohex;
                for (const auto &i : DEFAULT_ACTIONS) {
                    if (std::get<1>(i) == name) {
                        def_icohex = std::get<4>(i);
                        break;
                    }
                }
                if (!def_icohex.empty()) {
                    (void)set_hexcoded_icon(pixbuf, def_icohex);
                    row[action_cols.icon] = pixbuf;
                }
            }
        }
    }
    // Парсинг пользователей
    for (tinyxml2::XMLElement *table = root->FirstChildElement("Table");
         table != nullptr; table = table->NextSiblingElement("Table")) {
        const char *name = table->FirstChildElement("Name")->GetText();

        if (strcmp(name, "USERLIST") == 0) {
            tinyxml2::XMLElement *records = table->FirstChildElement("Records");
            if (!records)
                continue;
            for (tinyxml2::XMLElement *record =
                     records->FirstChildElement("Record");
                 record != nullptr;
                 record = record->NextSiblingElement("Record")) {
                Glib::ustring grpname = GetChildText(record, "GRPNAME");
                Gtk::TreeModel::iterator parent_iter;

                if (!grpname.empty()) {
                    parent_iter =
                        treestore_objs->get_iter(group_paths[grpname]);
                } else {
                    parent_iter = Gtk::TreeModel::iterator();
                }
                Gtk::TreeModel::iterator iter;
                if (treestore_objs->iter_is_valid(parent_iter)) {
                    Gtk::TreeModel::Row parent_row = *parent_iter;
                    iter = treestore_objs->append(parent_row.children());
                } else {
                    iter = treestore_objs->append();
                }
                Gtk::TreeModel::Row row = *iter;

                row[obj_cols.username] = GetChildText(record, "USERNAME");
                row[obj_cols.userpassw] = GetChildText(record, "USERPASSW");
                row[obj_cols.name] = GetChildText(record, "NAME");
                row[obj_cols.grpname] = grpname;
                row[obj_cols.extrainfo] = GetChildText(record, "FULLNAME");
                row[obj_cols.flags] = GetChildInt(record, "FLAGS");
                row[obj_cols.flags_] = GetChildText(record, "FLAGS_");
                row[obj_cols.allowtime] = GetChildText(record, "ALLOWTIME");
                row[obj_cols.registertime] =
                    GetChildText(record, "REGISTERTIME");
                row[obj_cols.lastentertime] =
                    GetChildText(record, "LASTENTERTIME");
                row[obj_cols.lastpwdchangetime] =
                    GetChildText(record, "LASTPWDCHANGETIME");
                row[obj_cols.pwdkeepperiod] =
                    GetChildInt(record, "PWDKEEPPERIOD");
                row[obj_cols.stations] = GetChildText(record, "STATIONS");
                row[obj_cols.droptimeout] = GetChildInt(record, "DROPTIMEOUT");
                row[obj_cols.psprdaccess] = GetChildText(record, "PSPRDACCESS");
                row[obj_cols.pspwraccess] = GetChildText(record, "PSPWRACCESS");
                row[obj_cols.psprdaccess_] =
                    GetChildText(record, "PSPRDACCESS_");
                row[obj_cols.pspwraccess_] =
                    GetChildText(record, "PSPWRACCESS_");
                row[obj_cols.priority_write] =
                    static_cast<bool>(GetChildInt(record, "PRIORITY_WRITE"));
                row[obj_cols.typeobject] = GetChildInt(record, "TYPEUSER");
                row[obj_cols.sid] = GetChildText(record, "SID");
                row[obj_cols.def_arm] = GetChildText(record, "DEF_ARM");
            }
        }
    }

    for (tinyxml2::XMLElement *table = root->FirstChildElement("Table");
         table != nullptr; table = table->NextSiblingElement("Table")) {
        const char *name = table->FirstChildElement("Name")->GetText();

        // Парсинг разрешений приложений пользователей
        if (strcmp(name, "ALLOWS") == 0) {
            tinyxml2::XMLElement *records = table->FirstChildElement("Records");
            if (!records)
                continue;
            for (tinyxml2::XMLElement *record =
                     records->FirstChildElement("Record");
                 record != nullptr;
                 record = record->NextSiblingElement("Record")) {
                Glib::ustring username = GetChildText(record, "USERNAME");
                Glib::ustring app_name = GetChildText(record, "APPNAME");
                Glib::ustring permissions_str =
                    GetChildText(record, "PERMISSIONS");
                // TODO:
                // int typeuser = GetChildInt(record, "TYPEUSER");
                Gtk::TreeModel::iterator iter =
                    get_by_name(username, treestore_objs, obj_cols, true);
                if (!iter)
                    continue;
                Gtk::TreeModel::Row row = *iter;

                std::vector<std::string> apps_names =
                    row[obj_cols.allows_apps_names];
                std::vector<bool> apps_enabled =
                    row[obj_cols.allows_apps_enabled];
                std::vector<unsigned char> apps_permissions =
                    row[obj_cols.allows_apps_permissions];
                set_app_permissions(app_name, apps_names, apps_enabled,
                                    permissions_str, apps_permissions);
                row[obj_cols.allows_apps_names] = apps_names;
                row[obj_cols.allows_apps_enabled] = apps_enabled;
                row[obj_cols.allows_apps_permissions] = apps_permissions;
            }
        }

        // Парсинг разрешений приложений групп
        if (strcmp(name, "ALLOWSGRP") == 0) {
            tinyxml2::XMLElement *records = table->FirstChildElement("Records");
            if (!records)
                continue;
            for (tinyxml2::XMLElement *record =
                     records->FirstChildElement("Record");
                 record != nullptr;
                 record = record->NextSiblingElement("Record")) {
                Glib::ustring group_name = GetChildText(record, "GRPNAME");
                Glib::ustring app_name = GetChildText(record, "APPNAME");
                Glib::ustring permissions_str =
                    GetChildText(record, "PERMISSIONS");
                // TODO:
                // int typeuser = GetChildInt(record, "TYPEGROUP");
                Gtk::TreeModel::iterator iter =
                    get_by_name(group_name, treestore_objs, obj_cols, false);
                if (!iter)
                    continue;
                Gtk::TreeModel::Row row = *iter;

                std::vector<std::string> apps_names =
                    row[obj_cols.allows_apps_names];
                std::vector<bool> apps_enabled =
                    row[obj_cols.allows_apps_enabled];
                std::vector<unsigned char> apps_permissions =
                    row[obj_cols.allows_apps_permissions];
                set_app_permissions(app_name, apps_names, apps_enabled,
                                    permissions_str, apps_permissions);
                row[obj_cols.allows_apps_names] = apps_names;
                row[obj_cols.allows_apps_enabled] = apps_enabled;
                row[obj_cols.allows_apps_permissions] = apps_permissions;
            }
        }
        // Парсинг разрешений зон пользователей
        if (strcmp(name, "ALLOWS_ZONES") == 0) {
            tinyxml2::XMLElement *records = table->FirstChildElement("Records");
            if (!records)
                continue;
            for (tinyxml2::XMLElement *record =
                     records->FirstChildElement("Record");
                 record != nullptr;
                 record = record->NextSiblingElement("Record")) {
                int station_id = GetChildInt(record, "STATIONID");
                std::string app_name =
                    static_cast<Glib::ustring>(GetChildText(record, "APPNAME"));
                std::string username = static_cast<Glib::ustring>(
                    GetChildText(record, "USERNAME"));
                unsigned char zone_permission =
                    GetChildInt(record, "PERMISSIONS");
                // TODO:
                // int typeuser = GetChildInt(record, "TYPEUSER");
                Gtk::TreeModel::iterator iter =
                    get_by_name(username, treestore_objs, obj_cols, true);
                if (!iter)
                    continue;
                Gtk::TreeModel::Row row = *iter;

                std::vector<std::string> zones_names =
                    row[obj_cols.allows_zones_names];
                std::vector<unsigned char> zones_permissions =
                    row[obj_cols.allows_zones_permissions];
                set_zone_permission(station_id, zones_names, zone_permission,
                                    zones_permissions);
                row[obj_cols.allows_zones_names] = zones_names;
                row[obj_cols.allows_zones_permissions] = zones_permissions;
            }
        }

        // Парсинг разрешений зон групп
        if (strcmp(name, "ALLOWS_ZONES_GROUP") == 0) {
            tinyxml2::XMLElement *records = table->FirstChildElement("Records");
            if (!records)
                continue;
            for (tinyxml2::XMLElement *record =
                     records->FirstChildElement("Record");
                 record != nullptr;
                 record = record->NextSiblingElement("Record")) {
                int station_id = GetChildInt(record, "STATIONID");
                std::string app_name =
                    static_cast<Glib::ustring>(GetChildText(record, "APPNAME"));
                std::string group_name =
                    static_cast<Glib::ustring>(GetChildText(record, "GRPNAME"));
                unsigned char zone_permission =
                    GetChildInt(record, "PERMISSIONS");
                // TODO:
                // int typeuser = GetChildInt(record, "TYPEGROUP");
                Gtk::TreeModel::iterator iter =
                    get_by_name(group_name, treestore_objs, obj_cols, false);
                if (!iter)
                    continue;
                Gtk::TreeModel::Row row = *iter;

                std::vector<std::string> zones_names =
                    row[obj_cols.allows_zones_names];
                std::vector<unsigned char> zones_permissions =
                    row[obj_cols.allows_zones_permissions];
                set_zone_permission(station_id, zones_names, zone_permission,
                                    zones_permissions);
                row[obj_cols.allows_zones_names] = zones_names;
                row[obj_cols.allows_zones_permissions] = zones_permissions;
            }
        }
    }

    return true;
}

int write_userlist_config(const std::string &config_path,
                          MainSettings &main_settings, std::string &errors) {
    Glib::KeyFile key_file;
    try {
        key_file.load_from_file(config_path);
    } catch (const Glib::Error &e) {
        errors += "- Не удалось загрузить файл конфигурации " + e.what() + "\n";
        return e.code();
    }

    try {
        if (!main_settings.new_users_config_path.empty()) {
            key_file.set_string("UserList", "DBFileName",
                                main_settings.new_users_config_path);
            main_settings.new_users_config_path.clear();
            key_file.set_string("UserList", "Style", "Simple");
            key_file.save_to_file(config_path);
        } else {
            key_file.set_integer("UserList", "TypeLogin",
                                 main_settings.type_login);
            key_file.set_string("UserList", "Style", main_settings.style);
            key_file.set_integer("UserList", "Synch_DBUsers",
                                 main_settings.synch_db_users);

            key_file.set_integer("KeyboardDisplay", "Visible",
                                 main_settings.keyboard_visible);
            key_file.set_integer("KeyboardDisplay", "BtnSize",
                                 main_settings.keyboard_button_size);
            key_file.set_integer("KeyboardDisplay", "BtnFontSize",
                                 main_settings.keyboard_button_font_size);
            key_file.set_integer("KeyboardDisplay", "BtnFontBold",
                                 main_settings.keyboard_button_font_bold);
            key_file.set_integer("KeyboardDisplay", "BtnFontItalic",
                                 main_settings.keyboard_button_font_italic);
            key_file.set_integer("KeyboardDisplay", "BtnFontUnderline",
                                 main_settings.keyboard_button_font_underline);
            key_file.set_integer("KeyboardDisplay", "BtnFontStrikeOut",
                                 main_settings.keyboard_button_font_strikeout);

            key_file.save_to_file(config_path);
        }
    } catch (const Glib::Error &e) {
        errors +=
            "- Не удалось сохранить файл конфигурации: " + e.what() + "\n";
    }

    // Удаление пустых строк между группами
    Glib::ustring data = key_file.to_data();
    GRegex *regex = g_regex_new("\n\n", static_cast<GRegexCompileFlags>(0),
                                static_cast<GRegexMatchFlags>(0), NULL);
    gchar *fixed_data =
        g_regex_replace_literal(regex, data.c_str(), -1, 0, "\n",
                                static_cast<GRegexMatchFlags>(0), NULL);
    g_regex_unref(regex);
    std::ofstream ofs(config_path);
    ofs << fixed_data;
    ofs.close();
    g_free(fixed_data);
    return 0;
}

int write_userlist_backup(const std::string &config_path, std::string &errors) {
    // Создание резервной копии файла конфигурации с сохранением прав
    // доступа оригинального файла
    std::ifstream src(config_path, std::ios::binary);
    if (!src.is_open())
        return errno;
    std::filesystem::path source_path(config_path);
    std::filesystem::path backup_path =
        source_path.parent_path() / "UserList.bak";
    std::ofstream dst(backup_path, std::ios::binary | std::ios::trunc);
    if (!dst.is_open()) {
        errors += "- Не удалось создать резервную копию файла конфигурации: " +
                  backup_path.string() + "\n";
        return errno;
    }
    dst << src.rdbuf();

    // Назначение прав доступа файлу резервной копии (только при
    // создании бекап файла впервые)
    std::error_code ec;
    auto perms = std::filesystem::status(source_path, ec).permissions();
    std::filesystem::permissions(backup_path, perms, ec);
    return 0;
}

int write_ldap_config(const std::string &config_path,
                      MainSettings &main_settings, std::string &errors) {
    Glib::KeyFile key_file;
    try {
        key_file.load_from_file(config_path);
    } catch (const Glib::Error &e) {
        errors +=
            "- Не удалось загрузить файл конфигурации: " + e.what() + "\n";
        return e.code();
    }

    try {
        key_file.set_string("Config", "ServerName",
                            main_settings.ldap_server_name);
        key_file.set_string("Config", "BaseDN", main_settings.ldap_base_dn);
        key_file.set_string("Config", "UserName", main_settings.ldap_user_name);
        key_file.set_string("Config", "Password",
                            main_settings.ldap_user_password);
        key_file.set_string("Config", "AdminGroup",
                            main_settings.ldap_admin_group);

        key_file.save_to_file(config_path);
    } catch (const Glib::Error &e) {
        errors +=
            "- Не удалось сохранить файл конфигурации: " + e.what() + "\n";
        return e.code();
    }

    // Удаление пустых строк между группами
    Glib::ustring data = key_file.to_data();
    GRegex *regex = g_regex_new("\n\n", static_cast<GRegexCompileFlags>(0),
                                static_cast<GRegexMatchFlags>(0), NULL);
    gchar *fixed_data =
        g_regex_replace_literal(regex, data.c_str(), -1, 0, "\n",
                                static_cast<GRegexMatchFlags>(0), NULL);
    g_regex_unref(regex);
    std::ofstream ofs(config_path);
    ofs << fixed_data;
    ofs.close();
    g_free(fixed_data);
    return 0;
}

int write_ldap_backup(const std::string &config_path, std::string &errors) {
    // Создание резервной копии файла конфигурации с сохранением прав
    // доступа оригинального файла
    std::ifstream src(config_path, std::ios::binary);
    if (!src.is_open())
        return errno;
    std::filesystem::path source_path(config_path);
    std::filesystem::path backup_path = source_path.parent_path() / "LDAP0.bak";
    std::ofstream dst(backup_path, std::ios::binary | std::ios::trunc);
    if (!dst.is_open()) {
        errors +=
            std::string(
                "- Не удалось создать резервную копию файла конфигурации: ") +
            backup_path.string() + "\n ";
        return errno;
    }
    dst << src.rdbuf();

    // Назначение прав доступа файлу резервной копии (только при
    // создании бекап файла впервые)
    std::error_code ec;
    auto perms = std::filesystem::status(source_path, ec).permissions();
    std::filesystem::permissions(backup_path, perms, ec);
    return 0;
}

int write_users_config(
    const std::string &config_path, const MainSettings &main_settings,
    const Glib::RefPtr<Gtk::TreeStore> &treestore_objs, const ObjCols &obj_cols,
    const Glib::RefPtr<Gtk::ListStore> &liststore_actions_apps,
    const Glib::RefPtr<Gtk::ListStore> &liststore_actions_private,
    const ActionCols &action_cols,
    const Glib::RefPtr<Gtk::TreeStore> &treestore_zones,
    const ZoneCols &zone_cols, std::string &errors) {
    tinyxml2::XMLDocument config;
    tinyxml2::XMLElement *root = config.NewElement("KSheriff_Cfg");
    config.InsertFirstChild(root);

    auto append_element = [&config](tinyxml2::XMLElement *parent,
                                    const char *name) {
        tinyxml2::XMLElement *node = config.NewElement(name);
        parent->InsertEndChild(node);
        return node;
    };
    auto delete_element = [&config](tinyxml2::XMLElement *parent,
                                    const char *name) {
        for (auto child = parent->FirstChildElement(name); child != nullptr;) {
            auto delete_child = child;
            child = child->NextSiblingElement(name);
            parent->DeleteChild(delete_child);
        }
    };
    auto append_val_element = [&config](tinyxml2::XMLElement *parent,
                                        const char *name, const char *val) {
        tinyxml2::XMLElement *node = config.NewElement(name);
        node->SetText(val);
        parent->InsertEndChild(node);
        return node;
    };
    auto permissions_to_str =
        [](const std::vector<unsigned char> &permissions) {
            std::string permissions_str = "";
            for (int i = 0; i < 25; ++i) {
                std::stringstream ss;
                ss << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(permissions[i]);
                permissions_str += ss.str();
            }
            std::size_t pos = permissions_str.find_last_not_of('0');
            if (pos != std::string::npos) {
                permissions_str.erase(pos + 1);
            } else {
                permissions_str.clear();
            }
            return permissions_str;
        };
    auto append_app_permissions = [&config, &permissions_to_str,
                                   &append_element,
                                   &obj_cols](tinyxml2::XMLElement *parent,
                                              const Gtk::TreeModel::Row &row,
                                              bool is_user) {
        std::vector<std::string> allows_apps_names =
            row[obj_cols.allows_apps_names];
        std::vector<bool> allows_apps_enabled =
            row[obj_cols.allows_apps_enabled];
        std::vector<unsigned char> allows_permissions =
            row[obj_cols.allows_apps_permissions];
        for (std::size_t i = 0; i < allows_apps_names.size(); ++i) {
            if (!allows_apps_enabled[i])
                continue;
            std::string allows_apps_name = allows_apps_names[i];
            std::string permissions_str = permissions_to_str(
                std::vector(allows_permissions.begin() + 25 * i,
                            allows_permissions.begin() + 25 * (i + 1)));
            if (permissions_str.empty())
                continue;

            tinyxml2::XMLElement *record = append_element(parent, "Record");
            append_tree_val_element_template(
                config, record, is_user ? "USERNAME" : "GRPNAME",
                is_user ? row[obj_cols.username] : row[obj_cols.name]);
            append_tree_val_element_template(config, record, "APPNAME",
                                             allows_apps_name);
            append_tree_val_element_template(config, record, "PERMISSIONS",
                                             permissions_str);
            append_tree_val_element_template(config, record,
                                             is_user ? "TYPEUSER" : "TYPEGROUP",
                                             row[obj_cols.typeobject]);
        }
    };
    auto append_zone_permissions =
        [&config, &append_element, &obj_cols](
            tinyxml2::XMLElement *parent, const Gtk::TreeModel::Row &row,
            const Glib::RefPtr<Gtk::TreeStore> &treestore_zones,
            const ZoneCols &zone_cols, bool is_user) {
            std::vector<std::string> allows_zones_names =
                row[obj_cols.allows_zones_names];
            std::vector<unsigned char> allows_zones_permissions =
                row[obj_cols.allows_zones_permissions];
            for (std::size_t i = 0; i < allows_zones_names.size(); ++i) {
                std::string zone_name = allows_zones_names[i];
                int station_id, group_id;
                for (auto &top_child_row : treestore_zones->children()) {
                    Glib::ustring top_chlild_zone_name =
                        top_child_row[zone_cols.zonename];
                    if (top_chlild_zone_name == zone_name) {
                        station_id = top_child_row[zone_cols.station_id];
                        group_id = top_child_row[zone_cols.group_id];
                        break;
                    }
                }
                tinyxml2::XMLElement *record = append_element(parent, "Record");
                append_tree_val_element_template(config, record, "STATIONID",
                                                 station_id);
                append_tree_val_element_template(config, record, "GROUPID",
                                                 group_id);
                append_tree_val_element_template(
                    config, record, is_user ? "USERNAME" : "GRPNAME",
                    is_user ? row[obj_cols.username] : row[obj_cols.name]);
                append_tree_val_element_template(config, record, "PERMISSIONS",
                                                 allows_zones_permissions[i]);
                append_tree_val_element_template(
                    config, record, is_user ? "TYPEUSER" : "TYPEGROUP",
                    row[obj_cols.typeobject]);
            }
        };

    // Запись пользователей
    tinyxml2::XMLElement *userlist = append_element(root, "Table");
    Glib::ustring default_user;
    for (auto &top_child_row : treestore_objs->children()) {
        for (auto &child_row : top_child_row.children()) {
            if ((child_row[obj_cols.flags] & SET_AS_DEF_USER) != 0) {
                default_user = child_row[obj_cols.username];
                break;
            }
        }
        if ((top_child_row[obj_cols.flags] & SET_AS_DEF_USER) != 0) {
            default_user = top_child_row[obj_cols.username];
            break;
        }
    }
    append_val_element(userlist, "Name", "USERLIST");
    tinyxml2::XMLElement *default_user_node = config.NewElement("DefaultUser");
    default_user_node->SetText(default_user.c_str());
    userlist->InsertEndChild(default_user_node);
    tinyxml2::XMLElement *userlist_columns =
        append_element(userlist, "Columns");
    append_val_element(userlist_columns, "Type", "8");
    append_val_element(userlist_columns, "Name", "USERNAME");
    append_val_element(userlist_columns, "Type", "8");
    append_val_element(userlist_columns, "Name", "USERPASSW");
    append_val_element(userlist_columns, "Type", "8");
    append_val_element(userlist_columns, "Name", "NAME");
    append_val_element(userlist_columns, "Type", "8");
    append_val_element(userlist_columns, "Name", "GRPNAME");
    append_val_element(userlist_columns, "Type", "8");
    append_val_element(userlist_columns, "Name", "FULLNAME");
    append_val_element(userlist_columns, "Type", "3");
    append_val_element(userlist_columns, "Name", "FLAGS");
    append_val_element(userlist_columns, "Type", "3");
    append_val_element(userlist_columns, "Name", "FLAGS_");
    append_val_element(userlist_columns, "Type", "8");
    append_val_element(userlist_columns, "Name", "ALLOWTIME");
    append_val_element(userlist_columns, "Type", "7");
    append_val_element(userlist_columns, "Name", "REGISTERTIME");
    append_val_element(userlist_columns, "Type", "7");
    append_val_element(userlist_columns, "Name", "LASTENTERTIME");
    append_val_element(userlist_columns, "Type", "7");
    append_val_element(userlist_columns, "Name", "LASTPWDCHANGETIME");
    append_val_element(userlist_columns, "Type", "2");
    append_val_element(userlist_columns, "Name", "PWDKEEPPERIOD");
    append_val_element(userlist_columns, "Type", "8");
    append_val_element(userlist_columns, "Name", "STATIONS");
    append_val_element(userlist_columns, "Type", "3");
    append_val_element(userlist_columns, "Name", "DROPTIMEOUT");
    append_val_element(userlist_columns, "Type", "8208");
    append_val_element(userlist_columns, "Name", "PSPRDACCESS");
    append_val_element(userlist_columns, "Type", "8208");
    append_val_element(userlist_columns, "Name", "PSPWRACCESS");
    append_val_element(userlist_columns, "Type", "8208");
    append_val_element(userlist_columns, "Name", "PSPRDACCESS_");
    append_val_element(userlist_columns, "Type", "8208");
    append_val_element(userlist_columns, "Name", "PSPWRACCESS_");
    append_val_element(userlist_columns, "Type", "16");
    append_val_element(userlist_columns, "Name", "PRIORITY_WRITE");
    append_val_element(userlist_columns, "Type", "16");
    append_val_element(userlist_columns, "Name", "TYPEUSER");
    append_val_element(userlist_columns, "Type", "8");
    append_val_element(userlist_columns, "Name", "SID");
    append_val_element(userlist_columns, "Type", "3");
    append_val_element(userlist_columns, "Name", "DEF_ARM");
    tinyxml2::XMLElement *userlist_records =
        append_element(userlist, "Records");
    for (auto &top_child_row : treestore_objs->children()) {
        Glib::ustring username = top_child_row[obj_cols.username];
        if (username.empty()) {
            for (auto &child_row : top_child_row->children()) {
                tinyxml2::XMLElement *record =
                    append_element(userlist_records, "Record");
                append_tree_val_element_template(config, record, "USERNAME",
                                                 child_row[obj_cols.username]);
                append_tree_val_element_template(config, record, "USERPASSW",
                                                 child_row[obj_cols.userpassw]);
                append_tree_val_element_template(config, record, "NAME",
                                                 child_row[obj_cols.name]);
                append_tree_val_element_template(config, record, "GRPNAME",
                                                 child_row[obj_cols.grpname]);
                append_tree_val_element_template(config, record, "FULLNAME",
                                                 child_row[obj_cols.extrainfo]);
                append_tree_val_element_template(config, record, "FLAGS",
                                                 child_row[obj_cols.flags]);
                append_tree_val_element_template(config, record, "FLAGS_",
                                                 child_row[obj_cols.flags_]);
                append_tree_val_element_template(config, record, "ALLOWTIME",
                                                 child_row[obj_cols.allowtime]);
                append_tree_val_element_template(
                    config, record, "REGISTERTIME",
                    child_row[obj_cols.registertime]);
                append_tree_val_element_template(
                    config, record, "LASTENTERTIME",
                    child_row[obj_cols.lastentertime]);
                append_tree_val_element_template(
                    config, record, "LASTPWDCHANGETIME",
                    child_row[obj_cols.lastpwdchangetime]);
                append_tree_val_element_template(
                    config, record, "PWDKEEPPERIOD",
                    child_row[obj_cols.pwdkeepperiod]);
                append_tree_val_element_template(config, record, "STATIONS",
                                                 child_row[obj_cols.stations]);
                append_tree_val_element_template(
                    config, record, "DROPTIMEOUT",
                    child_row[obj_cols.droptimeout]);
                append_tree_val_element_template(
                    config, record, "PSPRDACCESS",
                    child_row[obj_cols.psprdaccess]);
                append_tree_val_element_template(
                    config, record, "PSPWRACCESS",
                    child_row[obj_cols.pspwraccess]);
                append_tree_val_element_template(
                    config, record, "PSPRDACCESS_",
                    child_row[obj_cols.psprdaccess_]);
                append_tree_val_element_template(
                    config, record, "PSPWRACCESS_",
                    child_row[obj_cols.pspwraccess_]);
                append_tree_val_element_template(
                    config, record, "PRIORITY_WRITE",
                    child_row[obj_cols.priority_write]);
                append_tree_val_element_template(
                    config, record, "TYPEUSER", child_row[obj_cols.typeobject]);
                append_tree_val_element_template(config, record, "SID",
                                                 child_row[obj_cols.sid]);
                append_tree_val_element_template(config, record, "DEF_ARM",
                                                 child_row[obj_cols.def_arm]);
            }
            continue;
        }
        tinyxml2::XMLElement *record =
            append_element(userlist_records, "Record");
        append_tree_val_element_template(config, record, "USERNAME",
                                         top_child_row[obj_cols.username]);
        append_tree_val_element_template(config, record, "USERPASSW",
                                         top_child_row[obj_cols.userpassw]);
        append_tree_val_element_template(config, record, "NAME",
                                         top_child_row[obj_cols.name]);
        append_tree_val_element_template(config, record, "GRPNAME",
                                         top_child_row[obj_cols.grpname]);
        append_tree_val_element_template(config, record, "FULLNAME",
                                         top_child_row[obj_cols.extrainfo]);
        append_tree_val_element_template(config, record, "FLAGS",
                                         top_child_row[obj_cols.flags]);
        append_tree_val_element_template(config, record, "FLAGS_",
                                         top_child_row[obj_cols.flags_]);
        append_tree_val_element_template(config, record, "ALLOWTIME",
                                         top_child_row[obj_cols.allowtime]);
        append_tree_val_element_template(config, record, "REGISTERTIME",
                                         top_child_row[obj_cols.registertime]);
        append_tree_val_element_template(config, record, "LASTENTERTIME",
                                         top_child_row[obj_cols.lastentertime]);
        append_tree_val_element_template(
            config, record, "LASTPWDCHANGETIME",
            top_child_row[obj_cols.lastpwdchangetime]);
        append_tree_val_element_template(config, record, "PWDKEEPPERIOD",
                                         top_child_row[obj_cols.pwdkeepperiod]);
        append_tree_val_element_template(config, record, "STATIONS",
                                         top_child_row[obj_cols.stations]);
        append_tree_val_element_template(config, record, "DROPTIMEOUT",
                                         top_child_row[obj_cols.droptimeout]);
        append_tree_val_element_template(config, record, "PSPRDACCESS",
                                         top_child_row[obj_cols.psprdaccess]);
        append_tree_val_element_template(config, record, "PSPWRACCESS",
                                         top_child_row[obj_cols.pspwraccess]);
        append_tree_val_element_template(config, record, "PSPRDACCESS_",
                                         top_child_row[obj_cols.psprdaccess_]);
        append_tree_val_element_template(config, record, "PSPWRACCESS_",
                                         top_child_row[obj_cols.pspwraccess_]);
        append_tree_val_element_template(
            config, record, "PRIORITY_WRITE",
            top_child_row[obj_cols.priority_write]);
        append_tree_val_element_template(config, record, "TYPEUSER",
                                         top_child_row[obj_cols.typeobject]);
        append_tree_val_element_template(config, record, "SID",
                                         top_child_row[obj_cols.sid]);
        append_tree_val_element_template(config, record, "DEF_ARM",
                                         top_child_row[obj_cols.def_arm]);
    }
    if (userlist_records->FirstChildElement("Record") == nullptr) {
        delete_element(userlist, "Records");
    }

    // Запись групп
    tinyxml2::XMLElement *grouplist = append_element(root, "Table");
    append_val_element(grouplist, "Name", "GROUPLIST");
    tinyxml2::XMLElement *grouplist_columns =
        append_element(grouplist, "Columns");
    append_val_element(grouplist_columns, "Type", "8");
    append_val_element(grouplist_columns, "Name", "GRPNAME");
    append_val_element(grouplist_columns, "Type", "3");
    append_val_element(grouplist_columns, "Name", "FLAGS");
    append_val_element(grouplist_columns, "Type", "8");
    append_val_element(grouplist_columns, "Name", "ALLOWTIME");
    append_val_element(grouplist_columns, "Type", "2");
    append_val_element(grouplist_columns, "Name", "PWDKEEPPERIOD");
    append_val_element(grouplist_columns, "Type", "8");
    append_val_element(grouplist_columns, "Name", "DESCRIPTION");
    append_val_element(grouplist_columns, "Type", "8");
    append_val_element(grouplist_columns, "Name", "STATIONS");
    append_val_element(grouplist_columns, "Type", "3");
    append_val_element(grouplist_columns, "Name", "DROPTIMEOUT");
    append_val_element(grouplist_columns, "Type", "8208");
    append_val_element(grouplist_columns, "Name", "PSPRDACCESS");
    append_val_element(grouplist_columns, "Type", "8208");
    append_val_element(grouplist_columns, "Name", "PSPWRACCESS");
    append_val_element(grouplist_columns, "Type", "8208");
    append_val_element(grouplist_columns, "Name", "PSPRDACCESS_");
    append_val_element(grouplist_columns, "Type", "8208");
    append_val_element(grouplist_columns, "Name", "PSPWRACCESS_");
    append_val_element(grouplist_columns, "Type", "16");
    append_val_element(grouplist_columns, "Name", "PRIORITY_WRITE");
    append_val_element(grouplist_columns, "Type", "16");
    append_val_element(grouplist_columns, "Name", "TYPEGROUP");
    append_val_element(grouplist_columns, "Type", "8");
    append_val_element(grouplist_columns, "Name", "SID");
    tinyxml2::XMLElement *grouplist_records =
        append_element(grouplist, "Records");
    for (auto &top_child_row : treestore_objs->children()) {
        Glib::ustring username = top_child_row[obj_cols.username];
        if (username.empty()) {
            tinyxml2::XMLElement *record =
                append_element(grouplist_records, "Record");
            append_tree_val_element_template(config, record, "GRPNAME",
                                             top_child_row[obj_cols.name]);
            append_tree_val_element_template(config, record, "FLAGS",
                                             top_child_row[obj_cols.flags]);
            append_tree_val_element_template(config, record, "ALLOWTIME",
                                             top_child_row[obj_cols.allowtime]);
            append_tree_val_element_template(
                config, record, "PWDKEEPPERIOD",
                top_child_row[obj_cols.pwdkeepperiod]);
            append_tree_val_element_template(config, record, "DESCRIPTION",
                                             top_child_row[obj_cols.extrainfo]);
            append_tree_val_element_template(config, record, "STATIONS",
                                             top_child_row[obj_cols.stations]);
            append_tree_val_element_template(
                config, record, "DROPTIMEOUT",
                top_child_row[obj_cols.droptimeout]);
            append_tree_val_element_template(
                config, record, "PSPRDACCESS",
                top_child_row[obj_cols.psprdaccess]);
            append_tree_val_element_template(
                config, record, "PSPWRACCESS",
                top_child_row[obj_cols.pspwraccess]);
            append_tree_val_element_template(
                config, record, "PSPRDACCESS_",
                top_child_row[obj_cols.psprdaccess_]);
            append_tree_val_element_template(
                config, record, "PSPWRACCESS_",
                top_child_row[obj_cols.pspwraccess_]);
            append_tree_val_element_template(
                config, record, "PRIORITY_WRITE",
                top_child_row[obj_cols.priority_write]);
            append_tree_val_element_template(
                config, record, "TYPEGROUP",
                top_child_row[obj_cols.typeobject]);
            append_tree_val_element_template(config, record, "SID",
                                             top_child_row[obj_cols.sid]);
        }
    }
    if (grouplist_records->FirstChildElement("Record") == nullptr) {
        delete_element(grouplist, "Records");
    }

    // Запись разрешений действий для пользователей и групп
    tinyxml2::XMLElement *allows = append_element(root, "Table");
    append_val_element(allows, "Name", "ALLOWS");
    tinyxml2::XMLElement *allows_columns = append_element(allows, "Columns");
    append_val_element(allows_columns, "Type", "8");
    append_val_element(allows_columns, "Name", "USERNAME");
    append_val_element(allows_columns, "Type", "8");
    append_val_element(allows_columns, "Name", "APPNAME");
    append_val_element(allows_columns, "Type", "8208");
    append_val_element(allows_columns, "Name", "PERMISSIONS");
    append_val_element(allows_columns, "Type", "16");
    append_val_element(allows_columns, "Name", "TYPEUSER");
    tinyxml2::XMLElement *allows_apps_records =
        append_element(allows, "Records");
    tinyxml2::XMLElement *allowsgrp = append_element(root, "Table");
    append_val_element(allowsgrp, "Name", "ALLOWSGRP");
    tinyxml2::XMLElement *allowsgrp_columns =
        append_element(allowsgrp, "Columns");
    append_val_element(allowsgrp_columns, "Type", "8");
    append_val_element(allowsgrp_columns, "Name", "GRPNAME");
    append_val_element(allowsgrp_columns, "Type", "8");
    append_val_element(allowsgrp_columns, "Name", "APPNAME");
    append_val_element(allowsgrp_columns, "Type", "8208");
    append_val_element(allowsgrp_columns, "Name", "PERMISSIONS");
    append_val_element(allowsgrp_columns, "Type", "16");
    append_val_element(allowsgrp_columns, "Name", "TYPEGROUP");
    tinyxml2::XMLElement *allows_apps_group_records =
        append_element(allowsgrp, "Records");
    for (auto &top_child_row : treestore_objs->children()) {
        Glib::ustring username = top_child_row[obj_cols.username];
        if (username.empty()) {
            append_app_permissions(allows_apps_group_records, top_child_row,
                                   false);

            for (auto &child_row : top_child_row->children()) {
                append_app_permissions(allows_apps_records, child_row, true);
            }
        } else {
            append_app_permissions(allows_apps_records, top_child_row, true);
        }
    }
    if (allows_apps_records->FirstChildElement("Record") == nullptr) {
        delete_element(allows, "Records");
    }
    if (allows_apps_group_records->FirstChildElement("Record") == nullptr) {
        delete_element(allowsgrp, "Records");
    }

    // Запись списка приложений
    tinyxml2::XMLElement *applist = append_element(root, "Table");
    append_val_element(applist, "Name", "APPLIST");
    tinyxml2::XMLElement *applist_columns = append_element(applist, "Columns");
    append_val_element(applist_columns, "Type", "8");
    append_val_element(applist_columns, "Name", "APPNAME");
    append_val_element(applist_columns, "Type", "3");
    append_val_element(applist_columns, "Name", "FLAGS");
    append_val_element(applist_columns, "Type", "8");
    append_val_element(applist_columns, "Name", "GLOBACTMASK");
    append_val_element(applist_columns, "Type", "8");
    append_val_element(applist_columns, "Name", "DESCRIPTION");
    append_val_element(applist_columns, "Type", "8208");
    append_val_element(applist_columns, "Name", "ICO");
    append_val_element(applist_columns, "Type", "8");
    append_val_element(applist_columns, "Name", "GLOBACTMASK");
    tinyxml2::XMLElement *applist_records = append_element(applist, "Records");
    std::vector<std::string> apps_used = main_settings.apps_used;
    for (auto &app_row : liststore_actions_apps->children()) {
        Glib::ustring app_name = app_row[action_cols.appname];
        auto default_app_vec_iter = std::find_if(
            DEFAULT_APPS.begin(), DEFAULT_APPS.end(),
            [&app_name](const auto &i) { return std::get<0>(i) == app_name; });
        if (default_app_vec_iter == DEFAULT_APPS.end()) {
            continue;
        }
        int default_app_idx =
            std::distance(DEFAULT_APPS.begin(), default_app_vec_iter);
        tinyxml2::XMLElement *record =
            append_element(applist_records, "Record");
        append_tree_val_element_template(config, record, "APPNAME", app_name);
        append_tree_val_element_template(config, record, "FLAGS",
                                         app_row[action_cols.flags]);
        append_tree_val_element_template(config, record, "GLOBACTMASK",
                                         app_row[action_cols.globactmask]);
        append_tree_val_element_template(config, record, "DESCRIPTION",
                                         app_row[action_cols.description]);
        append_tree_val_element_template(
            config, record, "ICO", std::get<2>(DEFAULT_APPS[default_app_idx]));
        append_tree_val_element_template(config, record, "GLOBACTMASK",
                                         app_row[action_cols.globactmask]);
    }
    if (applist_records->FirstChildElement("Record") == nullptr) {
        delete_element(applist, "Records");
    }

    // Запись списка действий
    tinyxml2::XMLElement *actions = append_element(root, "Table");
    append_val_element(actions, "Name", "ACTIONS");
    tinyxml2::XMLElement *actions_columns = append_element(actions, "Columns");
    append_val_element(actions_columns, "Type", "8");
    append_val_element(actions_columns, "Name", "APPNAME");
    append_val_element(actions_columns, "Type", "8");
    append_val_element(actions_columns, "Name", "ACTIONNAME");
    append_val_element(actions_columns, "Type", "3");
    append_val_element(actions_columns, "Name", "ACTIONID");
    append_val_element(actions_columns, "Type", "3");
    append_val_element(actions_columns, "Name", "FLAGS");
    append_val_element(actions_columns, "Type", "8");
    append_val_element(actions_columns, "Name", "DESCRIPTION");
    append_val_element(actions_columns, "Type", "8208");
    append_val_element(actions_columns, "Name", "ICO");
    tinyxml2::XMLElement *actions_records = append_element(actions, "Records");
    int action_idx = 0;
    for (auto &action_row : liststore_actions_private->children()) {
        auto default_action = DEFAULT_ACTIONS[action_idx];
        if (std::find(apps_used.begin(), apps_used.begin(),
                      std::get<0>(default_action)) == apps_used.end()) {
            ++action_idx;
            continue;
        }
        tinyxml2::XMLElement *record =
            append_element(actions_records, "Record");
        append_tree_val_element_template(config, record, "APPNAME",
                                         action_row[action_cols.appname]);
        append_tree_val_element_template(config, record, "ACTIONNAME",
                                         action_row[action_cols.actionname]);
        append_tree_val_element_template(config, record, "ACTIONID",
                                         action_row[action_cols.action_id]);
        append_tree_val_element_template(config, record, "FLAGS",
                                         action_row[action_cols.flags]);
        append_tree_val_element_template(config, record, "DESCRIPTION",
                                         action_row[action_cols.description]);
        append_tree_val_element_template(config, record, "ICO",
                                         std::get<4>(default_action));
        ++action_idx;
    }
    if (actions_records->FirstChildElement("Record") == nullptr) {
        delete_element(actions, "Records");
    }

    // Запись станций
    tinyxml2::XMLElement *stations = append_element(root, "Table");
    append_val_element(stations, "Name", "STATIONS");
    tinyxml2::XMLElement *stations_columns =
        append_element(stations, "Columns");
    append_val_element(stations_columns, "Type", "8");
    append_val_element(stations_columns, "Name", "STATIONNAME");
    append_val_element(stations_columns, "Type", "3");
    append_val_element(stations_columns, "Name", "STATIONID");
    append_val_element(stations_columns, "Type", "3");
    append_val_element(stations_columns, "Name", "FLAGS");
    append_val_element(stations_columns, "Type", "8");
    append_val_element(stations_columns, "Name", "DESCRIPTION");
    append_val_element(stations_columns, "Type", "8");
    append_val_element(stations_columns, "Name", "MAC_ADDRESS");

    // Запись зон
    tinyxml2::XMLElement *zones = append_element(root, "Table");
    append_val_element(zones, "Name", "ZONES");
    tinyxml2::XMLElement *zones_columns = append_element(zones, "Columns");
    append_val_element(zones_columns, "Type", "8");
    append_val_element(zones_columns, "Name", "ZONENAME");
    append_val_element(zones_columns, "Type", "2");
    append_val_element(zones_columns, "Name", "STATIONID");
    append_val_element(zones_columns, "Type", "3");
    append_val_element(zones_columns, "Name", "GROUP_ID");
    append_val_element(zones_columns, "Type", "16");
    append_val_element(zones_columns, "Name", "MONOPLY_ACCESS");
    tinyxml2::XMLElement *zones_records = append_element(zones, "Records");
    for (auto &top_child_row : treestore_zones->children()) {
        bool is_exclusive_access = top_child_row[zone_cols.is_exclusive_access];
        if (is_exclusive_access) {
            append_tree_val_element_template(config, zones_records, "ZONENAME",
                                             top_child_row[zone_cols.zonename]);
            append_tree_val_element_template(
                config, zones_records, "STATIONID",
                top_child_row[zone_cols.station_id]);
            append_tree_val_element_template(config, zones_records, "GROUP_ID",
                                             top_child_row[zone_cols.group_id]);
            append_tree_val_element_template(
                config, zones_records, "MONOPLY_ACCESS", is_exclusive_access);
        }
    }
    if (zones_records->FirstChildElement("Record") == nullptr) {
        delete_element(zones, "Records");
    }

    // Запись разрешений зон для пользователей и групп
    tinyxml2::XMLElement *allows_zones = append_element(root, "Table");
    append_val_element(allows_zones, "Name", "ALLOWS_ZONES");
    tinyxml2::XMLElement *allows_zones_columns =
        append_element(allows_zones, "Columns");
    append_val_element(allows_zones_columns, "Type", "2");
    append_val_element(allows_zones_columns, "Name", "STATIONID");
    append_val_element(allows_zones_columns, "Type", "3");
    append_val_element(allows_zones_columns, "Name", "GROUP_ID");
    append_val_element(allows_zones_columns, "Type", "8");
    append_val_element(allows_zones_columns, "Name", "USERNAME");
    append_val_element(allows_zones_columns, "Type", "16");
    append_val_element(allows_zones_columns, "Name", "PERMISSIONS");
    append_val_element(allows_zones_columns, "Type", "16");
    append_val_element(allows_zones_columns, "Name", "TYPEUSER");
    tinyxml2::XMLElement *allows_zones_records =
        append_element(allows_zones, "Records");
    tinyxml2::XMLElement *allows_zones_group = append_element(root, "Table");
    append_val_element(allows_zones_group, "Name", "ALLOWS_ZONES_GROUP");
    tinyxml2::XMLElement *allows_zones_group_columns =
        append_element(allows_zones_group, "Columns");
    append_val_element(allows_zones_group_columns, "Type", "2");
    append_val_element(allows_zones_group_columns, "Name", "STATIONID");
    append_val_element(allows_zones_group_columns, "Type", "3");
    append_val_element(allows_zones_group_columns, "Name", "GROUP_ID");
    append_val_element(allows_zones_group_columns, "Type", "8");
    append_val_element(allows_zones_group_columns, "Name", "GRPNAME");
    append_val_element(allows_zones_group_columns, "Type", "16");
    append_val_element(allows_zones_group_columns, "Name", "PERMISSIONS");
    append_val_element(allows_zones_group_columns, "Type", "16");
    append_val_element(allows_zones_group_columns, "Name", "TYPEGROUP");
    tinyxml2::XMLElement *allows_zones_group_records =
        append_element(allows_zones_group, "Records");
    for (auto &top_child_row : treestore_objs->children()) {
        Glib::ustring username = top_child_row[obj_cols.username];
        if (username.empty()) {
            append_zone_permissions(allows_zones_group_records, top_child_row,
                                    treestore_zones, zone_cols, false);

            for (auto &child_row : top_child_row->children()) {
                append_zone_permissions(allows_zones_records, child_row,
                                        treestore_zones, zone_cols, true);
            }
        } else {
            append_zone_permissions(allows_zones_records, top_child_row,
                                    treestore_zones, zone_cols, true);
        }
    }
    if (allows_zones_records->FirstChildElement("Record") == nullptr) {
        delete_element(allows_zones, "Records");
    }
    if (allows_zones_group_records->FirstChildElement("Record") == nullptr) {
        delete_element(allows_zones_group, "Records");
    }

    std::filesystem::path users_p(config_path);
    if (!std::filesystem::exists(users_p.parent_path())) {
        std::error_code ec;
        // Создание родительской директории (SCADAProject/Base)
        // если она не существует и хватает прав
        std::filesystem::create_directory(users_p.parent_path(), ec);
        if (ec) {
            errors += "- Не удалось создать родительскую директорию: " +
                      users_p.parent_path().string() + "\n";
            return ec.value();
        }
    }
    std::ofstream f(config_path, std::ios::app);
    if (!f.is_open()) {
        f.close();
        std::error_code ec;
        if (ec) {
            errors += "- Не удалось создать файл базы данных "
                      "пользователей: " +
                      ec.message() + "\n";
        } else {
            errors += "- Недостаточно прав на запись файла базы данных "
                      "пользователей\n";
        }
        return ec.value();
    }
    f.close();
    int ret = config.SaveFile(config_path.c_str());
    if (ret != tinyxml2::XML_SUCCESS) {
        errors +=
            std::string(
                "- Не удалось сохранить файл базы данных пользователей: ") +
            config.ErrorStr();
        return ret;
    }
    return 0;
}
