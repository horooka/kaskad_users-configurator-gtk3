#include "kaskad_users-configurator-gtk3/utils.hpp"
#include <atomic>
#include <filesystem>
#include <gdk/gdkkeysyms.h>
#include <gdkmm.h>
#include <gtkmm.h>

#define TREE_MIN_WIDTH 200
#define PADDIND_WIDTH 100
#define FORM_MIN_WIDTH 600

class UserRightsConfigurator : public Gtk::Window {
    public:
        UserRightsConfigurator(std::string project_path)
            : userlist_config_path(
                  std::filesystem::path(project_path).parent_path().string() +
                  "/Configurator/UserList.ini"),
              ldap_config_path(
                  std::filesystem::path(project_path).parent_path().string() +
                  "/Configurator/LDAP0.ini") {
            button_apply.set_label("Применить");
            button_new_user.set_label("Добавить пользователя");
            button_new_group.set_label("Добавить группу");
            button_delete.set_label("Удалить");
            button_settings.set_label("Настройки");
            menuitem_save_label.set_text("Сохранить");
            menuitem_exit_label.set_text("Выход");
            menuitem_new_user_label.set_text("Добавить пользователя");
            menuitem_new_group_label.set_text("Добавить группу");
            menuitem_settings_label.set_text("Настройки");
            menuitem_delete_label.set_text("Удалить");
            menuitem_help_label.set_text("Справка");
            label_properties_group.set_text("Группа");
            label_properties_default_arm.set_text("АРМ по умолчанию");

            set_size_request(TREE_MIN_WIDTH + FORM_MIN_WIDTH + PADDIND_WIDTH,
                             400);
            setup_gresources();
            setup_menubuttons();
            setup_top_bar();
            setup_ui();
            setup_menus();
            setup_signals();
            setup_accel_groups();

            show_all_children();
            setup_data(project_path);
        }

    protected:
        void button_save_enable() {
            button_save_icon.set(pixbuf_save_enabled);
            menuitem_save_icon.set(pixbuf_save_enabled);
            button_save.set_sensitive(true);
            menuitem_save.set_sensitive(true);
            unsaved = true;
        }

        void button_save_disable() {
            button_save_icon.set(pixbuf_save_disabled);
            menuitem_save_icon.set(pixbuf_save_disabled);
            button_save.set_sensitive(false);
            menuitem_save.set_sensitive(false);
            unsaved = false;
        }

        void on_obj_selection_changed() {
            stored_curr_obj_row = *treeview.get_selection()->get_selected();
            if (!stored_curr_obj_row) {
                vbox_form.hide();
                button_save_disable();
                button_delete.set_sensitive(false);
                return;
            }
            vbox_form.show_all();
            button_delete.set_sensitive(true);
            Glib::ustring username = stored_curr_obj_row[obj_cols.username];
            if (username.empty()) {
                radiobuttons_form_buttons_bar[3]
                    ->hide(); // radiobutton_statistics_menu;
                if (curr_menu_idx == 3) {
                    radiobuttons_form_buttons_bar[4]->set_active(
                        true); // radiobutton_arms_menu;
                    curr_menu_idx = 4;
                }
            }

            switch (curr_menu_idx) {
            case 0:
                redraw_properties_menu();
                break;
            case 1:
                redraw_actions_menu();
                break;
            case 2:
                redraw_zones_menu();
                break;
            case 3:
                redraw_statistics_menu();
                break;
            case 4:
                redraw_arms_menu();
                break;
            }
        }

        // Назначение пароля пользователю без пароля
        bool ask_new_password(const std::string &message,
                              const Gtk::TreeModel::Row &obj_row) {
            Glib::ustring username = obj_row[obj_cols.username];
            Gtk::MessageDialog *dialog = new Gtk::MessageDialog(
                message + " для \"" +
                    static_cast<Glib::ustring>(obj_row[obj_cols.name]) + "\"",
                false, Gtk::MESSAGE_QUESTION, Gtk::BUTTONS_NONE);
            dialog->add_button("Отмена", Gtk::RESPONSE_CANCEL);
            dialog->add_button("Ok", Gtk::RESPONSE_OK);
            Gtk::Box *content_area = dialog->get_content_area();
            set_margin(*content_area, 5, 5);
            Gtk::Grid *grid = Gtk::make_managed<Gtk::Grid>();
            content_area->pack_start(*grid, Gtk::PACK_SHRINK);
            grid->set_column_spacing(25);
            grid->set_row_spacing(5);
            Gtk::Label *label_password_new =
                Gtk::make_managed<Gtk::Label>("Введите новый пароль:");
            label_password_new->set_halign(Gtk::ALIGN_START);
            Gtk::Entry *entry_password_new = Gtk::make_managed<Gtk::Entry>();
            entry_password_new->set_visibility(false);
            entry_password_new->set_input_purpose(Gtk::INPUT_PURPOSE_PASSWORD);
            grid->attach(*label_password_new, 0, 0, 1, 1);
            grid->attach(*entry_password_new, 1, 0, 1, 1);
            Gtk::Label *label_password_new_confirm =
                Gtk::make_managed<Gtk::Label>("Подтвердите новый пароль:");
            label_password_new_confirm->set_halign(Gtk::ALIGN_START);
            Gtk::Entry *entry_password_new_confirm =
                Gtk::make_managed<Gtk::Entry>();
            entry_password_new_confirm->set_visibility(false);
            entry_password_new_confirm->set_input_purpose(
                Gtk::INPUT_PURPOSE_PASSWORD);
            grid->attach(*label_password_new_confirm, 0, 1, 1, 1);
            grid->attach(*entry_password_new_confirm, 1, 1, 1, 1);
            Gtk::Separator *separator = Gtk::make_managed<Gtk::Separator>();
            content_area->pack_start(*separator, Gtk::PACK_SHRINK);
            set_margin(*separator, 0, 5);
            dialog->show_all();
            auto ok_button =
                dialog->get_widget_for_response(Gtk::ResponseType::RESPONSE_OK);
            entry_password_new->signal_changed().connect([&]() {
                ok_button->set_sensitive(
                    entry_password_new->get_text() ==
                    entry_password_new_confirm->get_text());
            });
            entry_password_new_confirm->signal_changed().connect([&]() {
                ok_button->set_sensitive(
                    entry_password_new->get_text() ==
                    entry_password_new_confirm->get_text());
            });

            int res = dialog->run();
            std::string new_password = entry_password_new->get_text();
            dialog->close();
            delete dialog;
            if (res == Gtk::RESPONSE_OK) {
                obj_row[obj_cols.userpassw] = md5_hash(new_password, username);
                return true;
            }
            return false;
        }

        void on_new_user_clicked() {
            Gtk::MessageDialog *dialog = new Gtk::MessageDialog(
                "Добавление пользователя", false, Gtk::MESSAGE_QUESTION,
                Gtk::BUTTONS_NONE);
            dialog->add_button("Отмена", Gtk::RESPONSE_CANCEL);
            dialog->add_button("OK", Gtk::RESPONSE_OK);
            Gtk::Box *content_area = dialog->get_content_area();
            std::atomic<bool> is_canceled(false);
            std::atomic<bool> is_loaded(false);
            set_margin(*content_area, 5, 5);

            // Дерево Active Directory
            Gtk::ScrolledWindow *scrolled_activedir =
                Gtk::make_managed<Gtk::ScrolledWindow>();
            content_area->pack_start(*scrolled_activedir,
                                     Gtk::PACK_EXPAND_WIDGET);
            Gtk::TreeView *treeview_activedir =
                Gtk::make_managed<Gtk::TreeView>();
            if (main_settings.synch_db_users) {
                activedir_parse_async(this, dialog, scrolled_activedir,
                                      treeview_activedir, main_settings,
                                      obj_cols, pixbuf_user, pixbuf_group,
                                      is_canceled, is_loaded);
            }

            Gtk::Grid *grid = Gtk::make_managed<Gtk::Grid>();
            grid->set_column_spacing(25);
            grid->set_row_spacing(5);
            content_area->pack_start(*grid, Gtk::PACK_SHRINK);
            Gtk::Label *label_name = Gtk::make_managed<Gtk::Label>("Имя:");
            Gtk::Entry *entry_name = Gtk::make_managed<Gtk::Entry>();
            label_name->set_halign(Gtk::ALIGN_START);
            grid->attach(*label_name, 0, 0, 1, 1);
            grid->attach(*entry_name, 1, 0, 1, 1);
            Gtk::Label *label_fullname =
                Gtk::make_managed<Gtk::Label>("Полное имя:");
            Gtk::Entry *entry_fullname = Gtk::make_managed<Gtk::Entry>();
            label_fullname->set_halign(Gtk::ALIGN_START);
            grid->attach(*label_fullname, 0, 1, 1, 1);
            grid->attach(*entry_fullname, 1, 1, 1, 1);
            Gtk::Label *label_password =
                Gtk::make_managed<Gtk::Label>("Пароль:");
            label_password->set_halign(Gtk::ALIGN_START);
            Gtk::Entry *entry_password = Gtk::make_managed<Gtk::Entry>();
            entry_password->set_visibility(false);
            entry_password->set_input_purpose(Gtk::INPUT_PURPOSE_PASSWORD);
            grid->attach(*label_password, 0, 2, 1, 1);
            grid->attach(*entry_password, 1, 2, 1, 1);
            Gtk::Label *label_password_confirm =
                Gtk::make_managed<Gtk::Label>("Подтвердите пароль:");
            label_password_confirm->set_halign(Gtk::ALIGN_START);
            Gtk::Entry *entry_password_confirm =
                Gtk::make_managed<Gtk::Entry>();
            entry_password_confirm->set_visibility(false);
            entry_password_confirm->set_input_purpose(
                Gtk::INPUT_PURPOSE_PASSWORD);
            grid->attach(*label_password_confirm, 0, 3, 1, 1);
            grid->attach(*entry_password_confirm, 1, 3, 1, 1);
            Gtk::Separator *separator1 = Gtk::make_managed<Gtk::Separator>();
            content_area->pack_start(*separator1, Gtk::PACK_SHRINK);
            set_margin(*separator1, 0, 5);

            // Предустановка группы в combobox в зависимости от выбранного
            // пользователя или группы
            Glib::ustring sugguested_group;
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            if (curr_obj_row) {
                Glib::ustring username = curr_obj_row[obj_cols.username];
                if (username.empty()) {
                    sugguested_group = curr_obj_row[obj_cols.name];
                } else {
                    sugguested_group = curr_obj_row[obj_cols.grpname];
                }
            }
            Gtk::Box *hbox_group =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_HORIZONTAL, 10);
            Gtk::Label *label_group = Gtk::make_managed<Gtk::Label>("Группа");
            Gtk::ComboBoxText *combobox_group =
                Gtk::make_managed<Gtk::ComboBoxText>();
            hbox_group->pack_start(*label_group, Gtk::PACK_SHRINK);
            hbox_group->pack_start(*combobox_group, Gtk::PACK_SHRINK);
            content_area->pack_start(*hbox_group, Gtk::PACK_SHRINK);
            set_margin(*combobox_group, 2, 10);
            combobox_group->set_size_request(75, -1);
            combobox_group->append("");
            for (const Gtk::TreeModel::Row &top_child_row :
                 treestore_objs->children()) {
                Glib::ustring username = top_child_row[obj_cols.username];
                if (username.empty()) {
                    Glib::ustring group_name = top_child_row[obj_cols.name];
                    combobox_group->append(group_name);
                }
            }
            combobox_group->set_active_text(sugguested_group);
            Gtk::Separator *separator2 = Gtk::make_managed<Gtk::Separator>();
            content_area->pack_start(*separator2, Gtk::PACK_SHRINK);
            set_margin(*separator2, 0, 5);
            auto ok_button =
                dialog->get_widget_for_response(Gtk::ResponseType::RESPONSE_OK);
            ok_button->set_sensitive(false);
            entry_name->signal_changed().connect([&]() {
                ok_button->set_sensitive(
                    !entry_name->get_text().empty() &&
                    !is_all_spaces(entry_name->get_text()) &&
                    entry_password->get_text() ==
                        entry_password_confirm->get_text());
            });
            entry_password->signal_changed().connect([&]() {
                ok_button->set_sensitive(
                    !entry_name->get_text().empty() &&
                    !is_all_spaces(entry_name->get_text()) &&
                    entry_password->get_text() ==
                        entry_password_confirm->get_text());
            });
            entry_password_confirm->signal_changed().connect([&]() {
                ok_button->set_sensitive(
                    !entry_name->get_text().empty() &&
                    !is_all_spaces(entry_name->get_text()) &&
                    entry_password->get_text() ==
                        entry_password_confirm->get_text());
            });
            treeview_activedir->get_selection()->signal_changed().connect(
                [&]() {
                    Gtk::TreeModel::Row curr_activedir_obj_row =
                        *treeview_activedir->get_selection()->get_selected();
                    if (!curr_activedir_obj_row)
                        return;
                    bool is_group =
                        static_cast<Glib::ustring>(
                            curr_activedir_obj_row[obj_cols.username])
                            .empty();
                    if (is_group) {
                        entry_name->set_text("");
                        entry_fullname->set_text("");
                    } else {
                        entry_name->set_text(static_cast<Glib::ustring>(
                            curr_activedir_obj_row[obj_cols.name]));
                        entry_fullname->set_text(static_cast<Glib::ustring>(
                            curr_activedir_obj_row[obj_cols.extrainfo]));
                    }
                });
            dialog->show_all();
            scrolled_activedir->hide();

            int res = dialog->run();
            Glib::ustring name = entry_name->get_text();
            Glib::ustring fullname = entry_fullname->get_text();
            Glib::ustring password = entry_password->get_text();
            Glib::ustring selected_group = combobox_group->get_active_text();
            dialog->close();
            is_canceled.store(true);
            if (is_loaded.load())
                delete dialog;
            if (res != Gtk::RESPONSE_OK)
                return;
            if (get_by_name(name, treestore_objs, obj_cols, true)) {
                Gtk::MessageDialog error_dialog(
                    std::string("Пользователь \"" + name + "\" уже существует"),
                    false, Gtk::MESSAGE_ERROR);
                error_dialog.run();
                return;
            }
            bool group = !selected_group.empty();
            Gtk::TreeModel::iterator new_iter;
            if (group) {
                Gtk::TreeModel::iterator group_iter;
                Gtk::TreeModel::Children top_childs =
                    treestore_objs->children();
                for (Gtk::TreeModel::iterator top_child_iter =
                         top_childs.begin();
                     top_child_iter != top_childs.end(); ++top_child_iter) {
                    if ((*top_child_iter)[obj_cols.name] == selected_group) {
                        group_iter = top_child_iter;
                        break;
                    }
                }
                new_iter = treestore_objs->append(group_iter->children());
                Gtk::TreeModel::Row curr_obj_row =
                    *treeview.get_selection()->get_selected();
                if (!treeview.row_expanded(
                        treestore_objs->get_path(curr_obj_row))) {
                    // Раскрытие группы при добавлении в нее
                    // пользователя
                    treeview.expand_row(treestore_objs->get_path(curr_obj_row),
                                        false);
                }
            } else {
                new_iter = treestore_objs->append();
            }
            Gtk::TreeModel::Row new_row = *new_iter;
            new_row[obj_cols.icon] = pixbuf_user;
            new_row[obj_cols.username] = name.uppercase();
            new_row[obj_cols.name] = name;
            new_row[obj_cols.extrainfo] = fullname;
            new_row[obj_cols.grpname] = sugguested_group;
            Glib::DateTime now = Glib::DateTime::create_now_local();
            new_row[obj_cols.pwdkeepperiod] = 6;
            new_row[obj_cols.registertime] = datetime_to_str(now);
            new_row[obj_cols.lastpwdchangetime] = datetime_to_str(now);
            new_row[obj_cols.lastentertime] = datetime_to_str(now);
            new_row[obj_cols.userpassw] = md5_hash(password, name.uppercase());
            treeview.get_selection()->select(new_iter);
            button_save_enable();
        }

        void on_new_group_clicked() {
            Gtk::MessageDialog *dialog = new Gtk::MessageDialog(
                "Добавление группы", false, Gtk::MESSAGE_QUESTION,
                Gtk::BUTTONS_NONE);
            dialog->add_button("Отмена", Gtk::RESPONSE_CANCEL);
            dialog->add_button("OK", Gtk::RESPONSE_OK);
            Gtk::Box *content_area = dialog->get_content_area();
            std::atomic<bool> is_canceled(false);
            std::atomic<bool> is_loaded(false);
            set_margin(*content_area, 5, 5);

            // Дерево Active Directory
            Gtk::ScrolledWindow *scrolled_activedir =
                Gtk::make_managed<Gtk::ScrolledWindow>();
            content_area->pack_start(*scrolled_activedir,
                                     Gtk::PACK_EXPAND_WIDGET);
            Gtk::TreeView *treeview_activedir =
                Gtk::make_managed<Gtk::TreeView>();
            if (main_settings.synch_db_users) {
                activedir_parse_async(this, dialog, scrolled_activedir,
                                      treeview_activedir, main_settings,
                                      obj_cols, pixbuf_user, pixbuf_group,
                                      is_canceled, is_loaded);
            }

            Gtk::Grid *grid = Gtk::make_managed<Gtk::Grid>();
            grid->set_column_spacing(25);
            grid->set_row_spacing(5);
            content_area->pack_start(*grid, Gtk::PACK_SHRINK);
            Gtk::Label *label_name = Gtk::make_managed<Gtk::Label>("Название:");
            Gtk::Entry *entry_name = Gtk::make_managed<Gtk::Entry>();
            label_name->set_halign(Gtk::ALIGN_START);
            grid->attach(*label_name, 0, 0, 1, 1);
            grid->attach(*entry_name, 1, 0, 1, 1);
            Gtk::Label *label_description =
                Gtk::make_managed<Gtk::Label>("Описание:");
            Gtk::Entry *entry_description = Gtk::make_managed<Gtk::Entry>();
            label_description->set_halign(Gtk::ALIGN_START);
            grid->attach(*label_description, 0, 1, 1, 1);
            grid->attach(*entry_description, 1, 1, 1, 1);
            Gtk::Separator *separator1 = Gtk::make_managed<Gtk::Separator>();
            content_area->pack_start(*separator1, Gtk::PACK_SHRINK);
            set_margin(*separator1, 0, 5);

            auto ok_button =
                dialog->get_widget_for_response(Gtk::ResponseType::RESPONSE_OK);
            ok_button->set_sensitive(false);
            entry_name->signal_changed().connect([&]() {
                ok_button->set_sensitive(!entry_name->get_text().empty());
            });
            treeview_activedir->get_selection()->signal_changed().connect(
                [&]() {
                    Gtk::TreeModel::Row curr_activedir_obj_row =
                        *treeview_activedir->get_selection()->get_selected();
                    if (!curr_activedir_obj_row)
                        return;
                    bool is_group =
                        static_cast<Glib::ustring>(
                            curr_activedir_obj_row[obj_cols.username])
                            .empty();
                    if (is_group) {
                        entry_name->set_text(static_cast<Glib::ustring>(
                            curr_activedir_obj_row[obj_cols.name]));
                        entry_description->set_text(static_cast<Glib::ustring>(
                            curr_activedir_obj_row[obj_cols.extrainfo]));
                    } else {
                        entry_name->set_text("");
                        entry_description->set_text("");
                    }
                });
            dialog->show_all();
            scrolled_activedir->hide();

            int res = dialog->run();
            std::string grpname = entry_name->get_text();
            std::string description = entry_description->get_text();
            dialog->close();
            is_canceled.store(true);
            if (is_loaded.load())
                delete dialog;
            if (res != Gtk::RESPONSE_OK)
                return;
            if (get_by_name(grpname, treestore_objs, obj_cols, false)) {
                Gtk::MessageDialog error_dialog(
                    std::string("Группа \"" + grpname + "\" уже существует"),
                    false, Gtk::MESSAGE_ERROR);
                error_dialog.run();
                return;
            }

            Gtk::TreeModel::Row new_row = *treestore_objs->append();
            new_row[obj_cols.icon] = pixbuf_group;
            new_row[obj_cols.name] = grpname;
            new_row[obj_cols.extrainfo] = description;
            combobox_properties_group.append(grpname);
            treeview.get_selection()->select(new_row);
            button_save_enable();
        }

        void on_save_clicked() {
            std::string errors;
            (void)write_users_config(
                users_config_path, main_settings, treestore_objs, obj_cols,
                liststore_actions_apps, liststore_actions_private, action_cols,
                treestore_zones, zone_cols, errors);
            if (errors.empty()) {
                button_save_disable();
                return;
            }
            Gtk::MessageDialog dialog(
                std::string("Не удалось сохранить файл базы "
                            "данных пользователей ") +
                    users_config_path + "\n\n" + errors,
                false, Gtk::MESSAGE_ERROR);
            dialog.run();
        }

        bool on_exit_clicked() {
            if (unsaved) {
                Gtk::MessageDialog dialog("Сохранить изменения?", false,
                                          Gtk::MESSAGE_QUESTION,
                                          Gtk::BUTTONS_NONE);
                dialog.add_button("Да", Gtk::RESPONSE_YES);
                dialog.add_button("Нет", Gtk::RESPONSE_NO);
                dialog.add_button("Отмена", Gtk::RESPONSE_CANCEL);

                int res = dialog.run();
                if (res == Gtk::RESPONSE_NO)
                    return false;
                if (res == Gtk::RESPONSE_YES) {
                    on_save_clicked();
                    if (unsaved)
                        return true;
                    return false;
                }
                return true;
            }
            return false;
        }

        void on_delete_clicked() {
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            if (!curr_obj_row)
                return;
            Glib::ustring username = curr_obj_row[obj_cols.username];
            Gtk::MessageDialog *dialog = new Gtk::MessageDialog(
                username.empty() ? "Вы уверены, что хотите удалить эту группу?"
                                 : "Вы уверены, что хотите удалить этого "
                                   "пользователя?",
                false, Gtk::MESSAGE_QUESTION, Gtk::BUTTONS_NONE);
            dialog->add_button("OK", Gtk::RESPONSE_YES);
            dialog->add_button("Отмена", Gtk::RESPONSE_CANCEL);
            int res = dialog->run();
            dialog->close();
            delete dialog;

            if (res != Gtk::RESPONSE_YES)
                return;
            if (username == "ADMIN") {
                Gtk::MessageDialog dialog(
                    "Нельзя удалить встроенную запись администратора", false,
                    Gtk::MESSAGE_ERROR);
                dialog.run();
                return;
            }
            treestore_objs->erase(curr_obj_row);
            button_save_enable();
        }

        void on_apply_name_clicked() {
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            if (!curr_obj_row)
                return;
            Glib::ustring username = curr_obj_row[obj_cols.username];
            if (username.empty()) {
                Glib::ustring curr_grpname = curr_obj_row[obj_cols.name];
                Glib::ustring new_grpname = entry_properties_name.get_text();
                curr_obj_row[obj_cols.name] = new_grpname;
                Gtk::TreeModel::Children group_childs =
                    get_by_name(new_grpname, treestore_objs, obj_cols, false)
                        ->children();
                for (Gtk::TreeModel::iterator iter = group_childs.begin();
                     iter != group_childs.end(); ++iter) {
                    (*iter)[obj_cols.grpname] = new_grpname;
                }
                combobox_properties_group.append(new_grpname);
                button_save_enable();
                return;
            }

            Glib::ustring hashed_password = curr_obj_row[obj_cols.userpassw];
            if (hashed_password.empty()) {
                ask_new_password("Назначение пароля", curr_obj_row);
                return;
            }

            Gtk::MessageDialog *dialog = new Gtk::MessageDialog(
                "Применить изменения", false, Gtk::MESSAGE_QUESTION,
                Gtk::BUTTONS_NONE);
            Gtk::Box *content_area = dialog->get_content_area();
            set_margin(*content_area, 5, 5);
            Gtk::Box *hbox =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_HORIZONTAL, 10);
            content_area->pack_start(*hbox, Gtk::PACK_SHRINK);
            Gtk::Label *label_password =
                Gtk::make_managed<Gtk::Label>("Пароль:");
            Gtk::Entry *entry_password = Gtk::make_managed<Gtk::Entry>();
            entry_password->set_visibility(false);
            entry_password->set_input_purpose(Gtk::INPUT_PURPOSE_PASSWORD);
            hbox->pack_start(*label_password, Gtk::PACK_SHRINK);
            hbox->pack_start(*entry_password, Gtk::PACK_EXPAND_WIDGET);
            Gtk::Separator *separator = Gtk::make_managed<Gtk::Separator>();
            content_area->pack_start(*separator, Gtk::PACK_SHRINK);
            set_margin(*separator, 0, 5);
            dialog->show_all();
            dialog->add_button("Отмена", Gtk::RESPONSE_CANCEL);
            dialog->add_button("Ok", Gtk::RESPONSE_OK);

            int res = dialog->run();
            Glib::ustring new_name = entry_properties_name.get_text();
            std::string entered_password = entry_password->get_text();
            dialog->close();
            delete dialog;
            if (res != Gtk::RESPONSE_OK) {
                redraw_properties_menu();
                return;
            }
            if (!check_password(username, entered_password, hashed_password)) {
                Gtk::MessageDialog dialog_error("Неверный пароль", false,
                                                Gtk::MESSAGE_ERROR);
                dialog_error.run();
                redraw_properties_menu();
                return;
            }
            if (get_by_name(new_name, treestore_objs, obj_cols,
                            username.empty() ? false : true)) {
                Gtk::MessageDialog error_dialog(
                    std::string(
                        (username.empty() ? "Группа \"" : "Пользователь \"") +
                        entry_properties_name.get_text() + "\" уже существует"),
                    false, Gtk::MESSAGE_ERROR);
                error_dialog.run();
                redraw_properties_menu();
                return;
            }
            curr_obj_row[obj_cols.userpassw] =
                md5_hash(entered_password, new_name.uppercase());
            curr_obj_row[obj_cols.username] = new_name.uppercase();
            curr_obj_row[obj_cols.name] = new_name;
            button_properties_apply_name.set_sensitive(false);
            button_save_enable();
            redraw_properties_menu();
        }

        void on_settings_clicked() {
            Gtk::MessageDialog dialog("Настройки", false, Gtk::MESSAGE_QUESTION,
                                      Gtk::BUTTONS_NONE);
            dialog.add_button("OK", Gtk::RESPONSE_OK);
            dialog.add_button("Отмена", Gtk::RESPONSE_CANCEL);
            Gtk::Box *content_area = dialog.get_content_area();
            set_margin(*content_area, 10, 10);
            Gtk::Stack *stack_settings = Gtk::make_managed<Gtk::Stack>();
            Gtk::RadioButton::Group group_settings;
            Gtk::RadioButton *radiobutton_settings_general =
                Gtk::make_managed<Gtk::RadioButton>(group_settings, "Общие");
            radiobutton_settings_general->set_mode(false);
            Gtk::RadioButton *radiobutton_settings_apps =
                Gtk::make_managed<Gtk::RadioButton>(group_settings,
                                                    "Приложения");
            radiobutton_settings_apps->set_mode(false);
            Gtk::Box *vbox_settings_general =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
            Gtk::Box *vbox_settings_apps =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
            Gtk::Box *hbox_radiobuttons_settings_bar =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_HORIZONTAL, 10);
            hbox_radiobuttons_settings_bar->pack_start(
                *radiobutton_settings_general, Gtk::PACK_SHRINK);
            hbox_radiobuttons_settings_bar->pack_start(
                *radiobutton_settings_apps, Gtk::PACK_SHRINK);
            content_area->pack_start(*hbox_radiobuttons_settings_bar,
                                     Gtk::PACK_SHRINK);
            content_area->pack_start(*stack_settings, Gtk::PACK_SHRINK);

            Gtk::Frame *frame_general_sync = Gtk::make_managed<Gtk::Frame>();
            Gtk::Label *label_general_sync =
                Gtk::make_managed<Gtk::Label>("Синхронизация БД пользователей");
            Gtk::Box *vbox_general_sync =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
            frame_general_sync->set_label_widget(*label_general_sync);
            frame_general_sync->add(*vbox_general_sync);
            vbox_settings_general->pack_start(*frame_general_sync,
                                              Gtk::PACK_SHRINK);
            Gtk::CheckButton *checkbutton_auto_sync =
                Gtk::make_managed<Gtk::CheckButton>(
                    "Производить синхронизацию пользователей при запуске");
            vbox_general_sync->pack_start(*checkbutton_auto_sync,
                                          Gtk::PACK_SHRINK);
            if (main_settings.synch_db_users)
                checkbutton_auto_sync->set_active(true);
            checkbutton_auto_sync->signal_toggled().connect(
                [this, &checkbutton_auto_sync]() {
                    main_settings.synch_db_users =
                        checkbutton_auto_sync->get_active();
                });
            set_margin(*frame_general_sync, 10, 10);
            set_margin(*vbox_general_sync, 10, 10);
            Gtk::Frame *frame_general_user_auth_type =
                Gtk::make_managed<Gtk::Frame>();
            Gtk::Label *label_general_user_auth_type =
                Gtk::make_managed<Gtk::Label>(
                    "Тип аутентификации пользователей");
            Gtk::Box *vbox_general_user_auth_type =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
            frame_general_user_auth_type->set_label_widget(
                *label_general_user_auth_type);
            frame_general_user_auth_type->add(*vbox_general_user_auth_type);
            vbox_settings_general->pack_start(*frame_general_user_auth_type,
                                              Gtk::PACK_SHRINK);
            Gtk::RadioButton::Group radiogroup_auth_type;
            Gtk::RadioButton *radiobutton_activedir_auth =
                Gtk::make_managed<Gtk::RadioButton>(
                    radiogroup_auth_type, "Средствами Active Directory");
            Gtk::RadioButton *radiobutton_kscada_auth =
                Gtk::make_managed<Gtk::RadioButton>(
                    radiogroup_auth_type,
                    "Средствами SCADA системы \"Каскад\"");
            vbox_general_user_auth_type->pack_start(*radiobutton_activedir_auth,
                                                    Gtk::PACK_SHRINK);
            vbox_general_user_auth_type->pack_start(*radiobutton_kscada_auth,
                                                    Gtk::PACK_SHRINK);
            if (main_settings.type_login == 1)
                radiobutton_activedir_auth->set_active(true);
            else
                radiobutton_kscada_auth->set_active(true);
            set_margin(*frame_general_user_auth_type, 10, 10);
            set_margin(*vbox_general_user_auth_type, 10, 10);
            Gtk::Frame *frame_general_ldap_auth_settings =
                Gtk::make_managed<Gtk::Frame>();
            Gtk::Label *label_general_ldap_authorization_settings =
                Gtk::make_managed<Gtk::Label>("Настройки авторизации по LDAP");
            Gtk::Box *vbox_general_ldap_authorization_settings =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
            frame_general_ldap_auth_settings->set_label_widget(
                *label_general_ldap_authorization_settings);
            frame_general_ldap_auth_settings->add(
                *vbox_general_ldap_authorization_settings);
            vbox_settings_general->pack_start(*frame_general_ldap_auth_settings,
                                              Gtk::PACK_SHRINK);
            Gtk::Grid *grid_general_ldap_authorization_settings =
                Gtk::make_managed<Gtk::Grid>();
            grid_general_ldap_authorization_settings->set_column_spacing(25);
            grid_general_ldap_authorization_settings->set_row_spacing(5);
            vbox_general_ldap_authorization_settings->pack_start(
                *grid_general_ldap_authorization_settings, Gtk::PACK_SHRINK);
            Gtk::Label *label_general_ldap_authorization_settings_server =
                Gtk::make_managed<Gtk::Label>("Сервер");
            label_general_ldap_authorization_settings_server->set_halign(
                Gtk::ALIGN_START);
            grid_general_ldap_authorization_settings->attach(
                *label_general_ldap_authorization_settings_server, 0, 0, 1, 1);
            Gtk::Entry *entry_general_ldap_authorization_settings_server_name =
                Gtk::make_managed<Gtk::Entry>();
            grid_general_ldap_authorization_settings->attach(
                *entry_general_ldap_authorization_settings_server_name, 1, 0, 1,
                1);
            Gtk::Label *label_general_ldap_authorization_settings_base_dn =
                Gtk::make_managed<Gtk::Label>("Base DN");
            label_general_ldap_authorization_settings_base_dn->set_halign(
                Gtk::ALIGN_START);
            grid_general_ldap_authorization_settings->attach(
                *label_general_ldap_authorization_settings_base_dn, 0, 1, 1, 1);
            Gtk::Entry *entry_general_ldap_authorization_settings_base_dn =
                Gtk::make_managed<Gtk::Entry>();
            grid_general_ldap_authorization_settings->attach(
                *entry_general_ldap_authorization_settings_base_dn, 1, 1, 1, 1);
            Gtk::Label *label_general_authorization_settings_user_name =
                Gtk::make_managed<Gtk::Label>("Пользователь");
            label_general_authorization_settings_user_name->set_halign(
                Gtk::ALIGN_START);
            grid_general_ldap_authorization_settings->attach(
                *label_general_authorization_settings_user_name, 0, 2, 1, 1);
            Gtk::Entry *entry_general_ldap_authorization_settings_user_name =
                Gtk::make_managed<Gtk::Entry>();
            grid_general_ldap_authorization_settings->attach(
                *entry_general_ldap_authorization_settings_user_name, 1, 2, 1,
                1);
            Gtk::Label
                *label_general_ldap_authorization_settings_user_password =
                    Gtk::make_managed<Gtk::Label>("Пароль");
            label_general_ldap_authorization_settings_user_password->set_halign(
                Gtk::ALIGN_START);
            grid_general_ldap_authorization_settings->attach(
                *label_general_ldap_authorization_settings_user_password, 0, 3,
                1, 1);
            Gtk::Entry
                *entry_general_ldap_authorization_settings_user_password =
                    Gtk::make_managed<Gtk::Entry>();
            grid_general_ldap_authorization_settings->attach(
                *entry_general_ldap_authorization_settings_user_password, 1, 3,
                1, 1);
            Gtk::Label *label_general_ldap_authorization_settings_admin_group =
                Gtk::make_managed<Gtk::Label>("Группа");
            label_general_ldap_authorization_settings_admin_group->set_halign(
                Gtk::ALIGN_START);
            grid_general_ldap_authorization_settings->attach(
                *label_general_ldap_authorization_settings_admin_group, 0, 4, 1,
                1);
            Gtk::Entry *entry_general_ldap_authorization_settings_admin_group =
                Gtk::make_managed<Gtk::Entry>();
            grid_general_ldap_authorization_settings->attach(
                *entry_general_ldap_authorization_settings_admin_group, 1, 4, 1,
                1);
            set_margin(*frame_general_ldap_auth_settings, 10, 10);
            set_margin(*vbox_general_ldap_authorization_settings, 10, 10);
            Gtk::Frame *frame_general_pwd_enter_settings =
                Gtk::make_managed<Gtk::Frame>();
            Gtk::Label *label_general_pwd_enter_settings =
                Gtk::make_managed<Gtk::Label>("Настройки ввода пароля");
            Gtk::Box *vbox_general_pwd_enter_settings =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
            frame_general_pwd_enter_settings->set_label_widget(
                *label_general_pwd_enter_settings);
            frame_general_pwd_enter_settings->add(
                *vbox_general_pwd_enter_settings);
            vbox_settings_general->pack_start(*frame_general_pwd_enter_settings,
                                              Gtk::PACK_SHRINK);
            Gtk::CheckButton *checkbutton_pwd_enter_settings_display_keyboard =
                Gtk::make_managed<Gtk::CheckButton>(
                    "Отображать экранную цифровую клавиатуру");
            vbox_general_pwd_enter_settings->pack_start(
                *checkbutton_pwd_enter_settings_display_keyboard,
                Gtk::PACK_SHRINK);
            checkbutton_pwd_enter_settings_display_keyboard->set_active(
                main_settings.keyboard_visible);
            Gtk::Frame *frame_general_pwd_enter_settings_buttons =
                Gtk::make_managed<Gtk::Frame>();
            Gtk::Label *label_general_pwd_enter_settings_buttons =
                Gtk::make_managed<Gtk::Label>("Кнопки");
            Gtk::Box *hbox_general_pwd_enter_settings_buttons =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_HORIZONTAL);
            frame_general_pwd_enter_settings_buttons->set_label_widget(
                *label_general_pwd_enter_settings_buttons);
            frame_general_pwd_enter_settings_buttons->add(
                *hbox_general_pwd_enter_settings_buttons);
            vbox_general_pwd_enter_settings->pack_start(
                *frame_general_pwd_enter_settings_buttons, Gtk::PACK_SHRINK);
            Gtk::SpinButton *spinbutton_general_pwd_enter_settings_button_size =
                Gtk::make_managed<Gtk::SpinButton>(
                    Gtk::Adjustment::create(0, 0, 100, 1));
            hbox_general_pwd_enter_settings_buttons->pack_start(
                *spinbutton_general_pwd_enter_settings_button_size,
                Gtk::PACK_SHRINK);
            Gtk::Button *button_general_pwd_enter_settings_button_font =
                Gtk::make_managed<Gtk::Button>("Шрифт");
            hbox_general_pwd_enter_settings_buttons->pack_start(
                *button_general_pwd_enter_settings_button_font,
                Gtk::PACK_SHRINK);
            set_margin(*button_general_pwd_enter_settings_button_font, 5, 0);
            checkbutton_pwd_enter_settings_display_keyboard->signal_toggled()
                .connect([this,
                          &checkbutton_pwd_enter_settings_display_keyboard,
                          &hbox_general_pwd_enter_settings_buttons]() {
                    main_settings.keyboard_visible =
                        checkbutton_pwd_enter_settings_display_keyboard
                            ->get_active();
                    hbox_general_pwd_enter_settings_buttons->set_sensitive(
                        main_settings.keyboard_visible);
                });
            hbox_general_pwd_enter_settings_buttons->set_sensitive(
                main_settings.keyboard_visible);
            spinbutton_general_pwd_enter_settings_button_size->set_value(
                main_settings.keyboard_button_size);
            spinbutton_general_pwd_enter_settings_button_size
                ->signal_value_changed()
                .connect([&]() {
                    main_settings.keyboard_button_size =
                        spinbutton_general_pwd_enter_settings_button_size
                            ->get_value();
                });
            button_general_pwd_enter_settings_button_font->signal_clicked()
                .connect([&]() {
                    Gtk::FontSelectionDialog dialog;
                    dialog.set_title("Выберите шрифт");
                    dialog.set_transient_for(*this);
                    dialog.set_modal(true);
                    Glib::ustring preset_font =
                        "Sans " +
                        std::to_string(main_settings.keyboard_button_font_size);
                    dialog.set_font_name(preset_font);
                    int res = dialog.run();
                    if (res != Gtk::RESPONSE_OK)
                        return;
                    auto font = dialog.get_font_name();
                    Pango::FontDescription font_desc(font);
                    main_settings.keyboard_button_font_size =
                        font_desc.get_size() / PANGO_SCALE;
                    main_settings.keyboard_button_font_italic =
                        font_desc.get_style() == Pango::STYLE_ITALIC;
                    // TODO:
                    /*main_settings.keyboard_button_font_underline =
                        font_desc.get_style() == Pango::STYLE_UNDERLINE;
                    main_settings.keyboard_button_font_strikeout =
                        font_desc.get_style() == Pango::STYLE_STRIKEOUT;
                    main_settings.keyboard_button_font_bold =
                        font_desc.get_style() == Pango::WEIGHT_BOLD;*/
                });
            checkbutton_pwd_enter_settings_display_keyboard->signal_toggled()
                .connect(
                    [this, &checkbutton_pwd_enter_settings_display_keyboard]() {
                        main_settings.keyboard_visible =
                            checkbutton_pwd_enter_settings_display_keyboard
                                ->get_active();
                    });
            set_margin(*frame_general_pwd_enter_settings_buttons, 0, 10);
            set_margin(*hbox_general_pwd_enter_settings_buttons, 10, 10);
            set_margin(*frame_general_pwd_enter_settings, 10, 10);
            set_margin(*vbox_general_pwd_enter_settings, 10, 10);
            Gtk::Frame *frame_general_deny_message_type =
                Gtk::make_managed<Gtk::Frame>();
            Gtk::Label *label_general_deny_message_type =
                Gtk::make_managed<Gtk::Label>("Вид запрещающего сообщения");
            Gtk::Box *vbox_general_deny_message_type =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
            frame_general_deny_message_type->set_label_widget(
                *label_general_deny_message_type);
            frame_general_deny_message_type->add(
                *vbox_general_deny_message_type);
            vbox_settings_general->pack_start(*frame_general_deny_message_type,
                                              Gtk::PACK_SHRINK);
            Gtk::ComboBoxText *combobox_general_deny_message_type =
                Gtk::make_managed<Gtk::ComboBoxText>();
            vbox_general_deny_message_type->pack_start(
                *combobox_general_deny_message_type, Gtk::PACK_SHRINK);
            combobox_general_deny_message_type->append("Простой");
            combobox_general_deny_message_type->append("Стандартный");
            combobox_general_deny_message_type->append("Продвинутый");
            Gtk::TextView *textview_general_deny_message_hint =
                Gtk::make_managed<Gtk::TextView>();
            Gtk::Box *box_textview =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL, 10);
            box_textview->pack_start(*textview_general_deny_message_hint,
                                     Gtk::PACK_SHRINK);
            box_textview->set_name("white-background");
            textview_general_deny_message_hint->set_editable(false);
            textview_general_deny_message_hint->set_wrap_mode(
                Gtk::WRAP_WORD_CHAR);
            vbox_general_deny_message_type->pack_start(*box_textview,
                                                       Gtk::PACK_SHRINK);
            set_margin(*textview_general_deny_message_hint, 10, 10);
            set_margin(*box_textview, 0, 10);
            std::string style = main_settings.style;
            Glib::RefPtr<Gtk::TextBuffer> text_buffer =
                textview_general_deny_message_hint->get_buffer();
            if (style == "Simple") {
                combobox_general_deny_message_type->set_active(0);
                text_buffer->set_text(
                    "Отображается сообщение об отсутствии прав у "
                    "пользователя на данное действие.");
            } else if (style == "Standard") {
                combobox_general_deny_message_type->set_active(1);
                text_buffer->set_text(
                    "Отображается диалог с сообщением об отсутствии "
                    "прав у пользователя на данное действие. Есть "
                    "возможность сменить "
                    "пользователя");
            } else if (style == "Advance") {
                combobox_general_deny_message_type->set_active(2);
                text_buffer->set_text(
                    "Отображается диалог с сообщением об отсутствии "
                    "прав у пользователя на данное действие. Есть "
                    "возможность ввести другого пользователя, а также "
                    "выбрать время бездействия, по прошествии которого "
                    "пользователь автоматически будет сменен на "
                    "предыдущего.");
            }
            combobox_general_deny_message_type->signal_changed().connect(
                [this, &combobox_general_deny_message_type,
                 &textview_general_deny_message_hint]() {
                    std::string style =
                        combobox_general_deny_message_type->get_active_text();
                    Glib::RefPtr<Gtk::TextBuffer> text_buffer =
                        textview_general_deny_message_hint->get_buffer();
                    if (style == "Простой") {
                        main_settings.style = "Simple";
                        text_buffer->set_text(
                            "Отображается сообщение об отсутствии прав у "
                            "пользователя на данное действие.");
                    } else if (style == "Стандартный") {
                        main_settings.style = "Standard";
                        text_buffer->set_text(
                            "Отображается диалог с сообщением об "
                            "отсутствии "
                            "прав у пользователя на данное действие. Есть "
                            "возможность сменить "
                            "пользователя");
                    } else if (style == "Продвинутый") {
                        main_settings.style = "Advance";
                        text_buffer->set_text(
                            "Отображается диалог с сообщением об "
                            "отсутствии "
                            "прав у пользователя на данное действие. Есть "
                            "возможность ввести другого пользователя, а "
                            "также "
                            "выбрать время бездействия, по прошествии "
                            "которого "
                            "пользователь автоматически будет сменен на "
                            "предыдущего.");
                    }
                });
            set_margin(*frame_general_deny_message_type, 10, 10);
            set_margin(*vbox_general_deny_message_type, 10, 10);
            entry_general_ldap_authorization_settings_server_name->set_text(
                main_settings.ldap_server_name);
            entry_general_ldap_authorization_settings_base_dn->set_text(
                main_settings.ldap_base_dn);
            entry_general_ldap_authorization_settings_user_name->set_text(
                main_settings.ldap_user_name);
            entry_general_ldap_authorization_settings_user_password->set_text(
                main_settings.ldap_user_password);
            entry_general_ldap_authorization_settings_admin_group->set_text(
                main_settings.ldap_admin_group);
            stack_settings->add(*vbox_settings_general);
            stack_settings->show_all();

            Gtk::TreeView *treeview_settings_apps =
                Gtk::make_managed<Gtk::TreeView>();
            Glib::RefPtr<Gtk::ListStore> liststore_settings_apps =
                Gtk::ListStore::create(action_cols);
            for (const Gtk::TreeModel::Row &row :
                 liststore_actions_apps->children()) {
                Gtk::TreeModel::Row new_row =
                    *liststore_settings_apps->append();
                new_row[action_cols.icon] =
                    static_cast<Glib::RefPtr<Gdk::Pixbuf>>(
                        row[action_cols.icon]);
                new_row[action_cols.appname] =
                    static_cast<Glib::ustring>(row[action_cols.appname]);
                new_row[action_cols.description] =
                    static_cast<Glib::ustring>(row[action_cols.description]);
            }
            treeview_settings_apps->set_model(liststore_settings_apps);
            treeview_settings_apps->get_selection()->set_mode(
                Gtk::SELECTION_MULTIPLE);
            treeview_settings_apps->get_selection()->select(
                liststore_settings_apps->children().begin());
            Gtk::TreeViewColumn *treecolumn_icon =
                Gtk::make_managed<Gtk::TreeViewColumn>();
            treeview_settings_apps->append_column(*treecolumn_icon);
            Gtk::CellRendererPixbuf *renderer_icon =
                Gtk::make_managed<Gtk::CellRendererPixbuf>();
            treecolumn_icon->pack_start(*renderer_icon, false);
            treecolumn_icon->add_attribute(renderer_icon->property_pixbuf(),
                                           action_cols.icon);
            Gtk::TreeViewColumn *treecolumn_description =
                Gtk::make_managed<Gtk::TreeViewColumn>();
            treecolumn_description->set_title("Приложения");
            treeview_settings_apps->append_column(*treecolumn_description);
            Gtk::CellRendererText *renderer_description =
                Gtk::make_managed<Gtk::CellRendererText>();
            treecolumn_description->pack_start(*renderer_description, false);
            treecolumn_description->add_attribute(
                renderer_description->property_text(), action_cols.description);
            Gtk::Button *button_delete_app =
                Gtk::make_managed<Gtk::Button>("Удалить выбранные приложения");
            vbox_settings_apps->pack_start(*button_delete_app,
                                           Gtk::PACK_SHRINK);
            button_delete_app->signal_clicked().connect(
                [this, &treeview_settings_apps, liststore_settings_apps]() {
                    Gtk::MessageDialog dialog("Удаление выбранных приложений",
                                              false, Gtk::MESSAGE_QUESTION,
                                              Gtk::BUTTONS_NONE);
                    dialog.add_button("OK", Gtk::RESPONSE_OK);
                    dialog.add_button("Отмена", Gtk::RESPONSE_CANCEL);
                    int res = dialog.run();
                    if (res != Gtk::RESPONSE_OK)
                        return;

                    auto selected_paths =
                        treeview_settings_apps->get_selection()
                            ->get_selected_rows();
                    for (const auto &path : selected_paths) {
                        Gtk::TreeModel::Row row =
                            *liststore_settings_apps->get_iter(path);
                        if (!row)
                            continue;
                        Glib::ustring app_name = row[action_cols.appname];
                        std::vector<std::string> &apps_used =
                            main_settings.apps_used;
                        apps_used.erase(std::remove(apps_used.begin(),
                                                    apps_used.end(), app_name),
                                        apps_used.end());
                        liststore_settings_apps->erase(row);
                    }
                    Gtk::TreeModel::iterator first_app =
                        liststore_settings_apps->children().begin();
                    if (first_app) {
                        treeview_settings_apps->get_selection()->unselect_all();
                        treeview_settings_apps->get_selection()->select(
                            first_app);
                    }
                    button_save_enable();
                });
            Gtk::Frame *frame_settings_apps = Gtk::make_managed<Gtk::Frame>();
            frame_settings_apps->set_name("white-background");
            frame_settings_apps->add(*treeview_settings_apps);
            vbox_settings_apps->pack_start(*frame_settings_apps,
                                           Gtk::PACK_EXPAND_WIDGET);
            set_margin(*frame_settings_apps, 10, 10);
            set_margin(*treeview_settings_apps, 10, 10);
            stack_settings->add(*vbox_settings_apps);
            stack_settings->show_all();
            radiobutton_settings_general->signal_toggled().connect([&]() {
                stack_settings->set_visible_child(*vbox_settings_general);
            });
            radiobutton_settings_apps->signal_toggled().connect([&]() {
                stack_settings->set_visible_child(*vbox_settings_apps);
            });
            radiobutton_settings_apps->set_active(true);

            dialog.show_all();
            int res = dialog.run();
            if (res != Gtk::RESPONSE_OK)
                return;
            Gtk::TreeModel::iterator iter =
                liststore_actions_apps->children().begin();
            while (iter != liststore_actions_apps->children().end()) {
                const auto &app_row = *iter;
                Glib::ustring app_name = app_row[action_cols.appname];
                std::vector<std::string> apps_used = main_settings.apps_used;

                if (std::find(apps_used.begin(), apps_used.end(), app_name) ==
                    apps_used.end()) {
                    iter = liststore_actions_apps->erase(iter);
                } else {
                    ++iter;
                }
            }
            main_settings.synch_db_users = checkbutton_auto_sync->get_active();
            main_settings.type_login =
                radiobutton_activedir_auth->get_active() ? 1 : 2;
            main_settings.ldap_server_name =
                entry_general_ldap_authorization_settings_server_name
                    ->get_text();
            main_settings.ldap_base_dn =
                entry_general_ldap_authorization_settings_base_dn->get_text();
            main_settings.ldap_user_name =
                entry_general_ldap_authorization_settings_user_name->get_text();
            main_settings.ldap_user_password =
                entry_general_ldap_authorization_settings_user_password
                    ->get_text();
            main_settings.ldap_admin_group =
                entry_general_ldap_authorization_settings_admin_group
                    ->get_text();
            std::string errors;
            int ret_backup_userlist =
                write_userlist_backup(userlist_config_path, errors);
            if (ret_backup_userlist == 0)
                (void)write_userlist_config(userlist_config_path, main_settings,
                                            errors);
            int ret_backup_ldap = write_ldap_backup(ldap_config_path, errors);
            if (ret_backup_ldap == 0)
                (void)write_ldap_config(ldap_config_path, main_settings,
                                        errors);
            if (!errors.empty()) {
                Gtk::MessageDialog dialog(
                    "Не удалось сохранить файлы конфигурации\n\n" + errors,
                    false, Gtk::MESSAGE_ERROR);
                dialog.run();
            }
        }

        void redraw_properties_menu() {
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            Glib::ustring username = curr_obj_row[obj_cols.username];
            unsigned char flags = curr_obj_row[obj_cols.flags];
            unsigned char group_flags_store = 0;
            checkbutton_assign_admin_rights.set_sensitive(username != "ADMIN");
            checkbutton_allow_password_change.set_sensitive(true);
            checkbutton_allow_to_set_as_default_user.set_sensitive(true);
            if (username.empty()) {
                label_properties_is_group.set_text("Группа");
            } else {
                label_properties_is_group.set_text("");
                combobox_properties_group.set_active_text(
                    curr_obj_row[obj_cols.grpname]);
                Glib::ustring default_arm = curr_obj_row[obj_cols.def_arm];
                if (default_arm.empty()) {
                    combobox_properties_arms.set_active(-1);
                } else {
                    combobox_properties_arms.set_active_text(default_arm);
                }
                // Отключение возможности редактирования чекбоксов
                // пользователя если он включен для его группы
                Glib::ustring group_name = curr_obj_row[obj_cols.grpname];
                if (!group_name.empty()) {
                    unsigned char group_flags =
                        (*get_by_name(group_name, treestore_objs, obj_cols,
                                      false))[obj_cols.flags];
                    if ((group_flags & HAVE_ADMIN_RIGHTS) != 0) {
                        group_flags_store |= HAVE_ADMIN_RIGHTS;
                        checkbutton_assign_admin_rights.set_sensitive(false);
                    } else {
                        checkbutton_assign_admin_rights.set_sensitive(true);
                    }
                    if ((group_flags & ALLOW_PWD_CHANGE) != 0) {
                        group_flags_store |= ALLOW_PWD_CHANGE;
                        checkbutton_allow_password_change.set_sensitive(false);
                    } else {
                        checkbutton_allow_password_change.set_sensitive(true);
                    }
                    if ((group_flags & ALLOW_TO_SET_AS_DEF_USER) != 0) {
                        group_flags_store |= ALLOW_TO_SET_AS_DEF_USER;
                        checkbutton_allow_to_set_as_default_user.set_sensitive(
                            false);
                    } else {
                        checkbutton_allow_to_set_as_default_user.set_sensitive(
                            true);
                    }
                }
            }
            label_info.set_text(curr_obj_row[obj_cols.name]);
            entry_properties_name.set_text(curr_obj_row[obj_cols.name]);
            entry_properties_extrainfo.set_text(
                curr_obj_row[obj_cols.extrainfo]);
            spinbutton_properties_password_expiration.set_value(
                curr_obj_row[obj_cols.pwdkeepperiod]);
            checkbutton_assign_admin_rights.set_active(
                (flags & HAVE_ADMIN_RIGHTS) != 0 ||
                (group_flags_store & HAVE_ADMIN_RIGHTS) != 0);
            checkbutton_allow_password_change.set_active(
                (flags & ALLOW_PWD_CHANGE) != 0 ||
                (group_flags_store & ALLOW_PWD_CHANGE) != 0);
            checkbutton_allow_to_set_as_default_user.set_active(
                (flags & ALLOW_TO_SET_AS_DEF_USER) != 0 ||
                (group_flags_store & ALLOW_TO_SET_AS_DEF_USER) != 0);
            checkbutton_require_password_change_on_next_login.set_active(
                (flags & REQUIRE_PWD_CHANGE_ON_NEXT_LOGIN) != 0 ||
                (group_flags_store & REQUIRE_PWD_CHANGE_ON_NEXT_LOGIN) != 0);
            checkbutton_set_as_default_user.set_active(
                (flags & SET_AS_DEF_USER) != 0);
            stack_menu.show_all();
            if (username.empty()) {
                checkbutton_require_password_change_on_next_login.hide();
                checkbutton_set_as_default_user.hide();
                label_properties_group.hide();
                combobox_properties_group.hide();
                label_properties_default_arm.hide();
                combobox_properties_arms.hide();
                button_properties_change_password.hide();
            }

            stack_menu.set_visible_child(*menus[0]);
            curr_menu_idx = 0;
        }

        void redraw_actions_menu() {
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            unsigned char flags = curr_obj_row[obj_cols.flags];
            if ((flags & HAVE_ADMIN_RIGHTS) != 0) {
                stack_menu.set_visible_child(*menus[5]);
                curr_menu_idx = 1;
                return;
            }
            if (!menus[1]) {
                Gtk::Box *vbox_menu2 =
                    Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
                Gtk::Paned *paned_actions_main =
                    Gtk::make_managed<Gtk::Paned>(Gtk::ORIENTATION_HORIZONTAL);
                vbox_menu2->pack_start(*paned_actions_main, true, true);
                Gtk::ScrolledWindow *scrolled_actions_apps =
                    Gtk::make_managed<Gtk::ScrolledWindow>();
                scrolled_actions_apps->set_name("white-background");
                scrolled_actions_apps->set_policy(Gtk::POLICY_AUTOMATIC,
                                                  Gtk::POLICY_AUTOMATIC);
                scrolled_actions_apps->add(treeview_actions_apps);
                Gtk::Frame *frame_actions_apps =
                    Gtk::make_managed<Gtk::Frame>();
                frame_actions_apps->add(*scrolled_actions_apps);
                Gtk::Paned *paned_actions_public_private =
                    Gtk::make_managed<Gtk::Paned>(Gtk::ORIENTATION_VERTICAL);
                paned_actions_main->pack1(*frame_actions_apps, true, true);
                paned_actions_main->pack2(*paned_actions_public_private, true,
                                          true);
                frame_actions_apps->set_margin_right(10);
                set_margin(treeview_actions_apps, 10, 10);
                Gtk::ScrolledWindow *scrolled_actions_public =
                    Gtk::make_managed<Gtk::ScrolledWindow>();
                scrolled_actions_public->set_name("white-background");
                scrolled_actions_public->set_policy(Gtk::POLICY_AUTOMATIC,
                                                    Gtk::POLICY_AUTOMATIC);
                scrolled_actions_public->add(treeview_actions_public);
                Gtk::Frame *frame_actions_public =
                    Gtk::make_managed<Gtk::Frame>();
                frame_actions_public->add(*scrolled_actions_public);
                paned_actions_public_private->pack1(*frame_actions_public, true,
                                                    true);
                Gtk::ScrolledWindow *scrolled_actions_private =
                    Gtk::make_managed<Gtk::ScrolledWindow>();
                scrolled_actions_private->set_name("white-background");
                scrolled_actions_private->set_policy(Gtk::POLICY_AUTOMATIC,
                                                     Gtk::POLICY_AUTOMATIC);
                scrolled_actions_private->add(treeview_actions_private);
                Gtk::Frame *frame_actions_private =
                    Gtk::make_managed<Gtk::Frame>();
                frame_actions_private->add(*scrolled_actions_private);
                paned_actions_public_private->pack2(*frame_actions_private,
                                                    true, true);
                vbox_menu2->set_margin_top(10);
                frame_actions_public->set_margin_bottom(10);
                frame_actions_public->set_margin_left(10);
                frame_actions_private->set_margin_top(10);
                frame_actions_private->set_margin_left(10);
                set_margin(treeview_actions_public, 10, 10);
                set_margin(treeview_actions_private, 10, 10);

                Gtk::CellRendererToggle *renderer_toggle_apps =
                    Gtk::make_managed<Gtk::CellRendererToggle>();
                renderer_toggle_apps->signal_toggled().connect(
                    [this](const Glib::ustring &path) {
                        Gtk::TreeModel::Row curr_obj_row =
                            *treeview.get_selection()->get_selected();
                        Gtk::TreeModel::Row curr_app_row =
                            *liststore_actions_apps->get_iter(path);
                        if (!curr_app_row)
                            return;

                        bool curr_val = curr_app_row[action_cols.is_enabled];
                        curr_app_row[action_cols.is_enabled] = !curr_val;
                        treeview_actions_public.set_sensitive(!curr_val);
                        treeview_actions_private.set_sensitive(!curr_val);
                        std::string app_name = static_cast<Glib::ustring>(
                            curr_app_row[action_cols.appname]);
                        std::vector<std::string> apps_names =
                            curr_obj_row[obj_cols.allows_apps_names];
                        std::vector<bool> apps_enabled =
                            curr_obj_row[obj_cols.allows_apps_enabled];
                        std::vector<unsigned char> apps_permissions =
                            curr_obj_row[obj_cols.allows_apps_permissions];
                        change_app_enabled(app_name, apps_names, !curr_val,
                                           apps_enabled, apps_permissions);
                        curr_obj_row[obj_cols.allows_apps_names] = apps_names;
                        curr_obj_row[obj_cols.allows_apps_enabled] =
                            apps_enabled;
                        curr_obj_row[obj_cols.allows_apps_permissions] =
                            apps_permissions;
                        button_save_enable();
                    });
                Gtk::TreeViewColumn *treecolumn_toggle_icon_apps =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_toggle_icon_apps->pack_start(*renderer_toggle_apps,
                                                        false);
                treecolumn_toggle_icon_apps->add_attribute(
                    renderer_toggle_apps->property_active(),
                    action_cols.is_enabled);
                treeview_actions_apps.set_model(liststore_actions_apps);
                treeview_actions_apps.append_column(
                    *treecolumn_toggle_icon_apps);
                Gtk::CellRendererPixbuf *renderer_icon_apps =
                    Gtk::make_managed<Gtk::CellRendererPixbuf>();
                treecolumn_toggle_icon_apps->pack_start(*renderer_icon_apps,
                                                        false);
                treecolumn_toggle_icon_apps->add_attribute(
                    renderer_icon_apps->property_pixbuf(), action_cols.icon);
                Gtk::CellRendererToggle *renderer_toggle_apps_group =
                    Gtk::make_managed<Gtk::CellRendererToggle>();
                renderer_toggle_apps_group->set_sensitive(false);
                treecolumn_toggle_apps_group.pack_start(
                    *renderer_toggle_apps_group, false);
                treecolumn_toggle_apps_group.add_attribute(
                    renderer_toggle_apps_group->property_active(),
                    action_cols.is_enabled_group);
                treeview_actions_apps.append_column(
                    treecolumn_toggle_apps_group);
                Gtk::TreeViewColumn *treecolumn_description_apps =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_description_apps->set_title("Приложения");
                treeview_actions_apps.append_column(
                    *treecolumn_description_apps);
                Gtk::CellRendererText *renderer_description_apps =
                    Gtk::make_managed<Gtk::CellRendererText>();
                treecolumn_description_apps->pack_start(
                    *renderer_description_apps, false);
                treecolumn_description_apps->add_attribute(
                    renderer_description_apps->property_text(),
                    action_cols.description);

                liststore_actions_public = Gtk::ListStore::create(action_cols);
                public_filter_model =
                    Gtk::TreeModelFilter::create(liststore_actions_public);
                public_filter_model->set_visible_func(
                    [this](const Gtk::TreeModel::const_iterator &iter) -> bool {
                        if (!iter)
                            return false;
                        Gtk::TreeModel::Row row = *iter;
                        return row[action_cols.is_visible];
                    });
                CellRendererThreeState *renderer_toggle_public =
                    Gtk::make_managed<CellRendererThreeState>(
                        action_cols.is_threestate.index());
                renderer_toggle_public->signal_toggled().connect(
                    [this](const Glib::ustring &path) {
                        Gtk::TreeModel::Row curr_obj_row =
                            *treeview.get_selection()->get_selected();
                        Gtk::TreePath filtered_path(path);
                        Gtk::TreePath base_path =
                            public_filter_model->convert_path_to_child_path(
                                filtered_path);
                        Gtk::TreeModel::iterator iter =
                            liststore_actions_public->get_iter(base_path);
                        if (!iter)
                            return;
                        int state = (*iter)[action_cols.is_threestate];
                        state = (state + 1) % 3;
                        (*iter)[action_cols.is_threestate] = state;
                        Gtk::TreeModel::Row curr_app_row =
                            *treeview_actions_apps.get_selection()
                                 ->get_selected();
                        Glib::ustring app_name =
                            curr_app_row[action_cols.appname];
                        std::vector<std::string> apps_names =
                            curr_obj_row[obj_cols.allows_apps_names];
                        std::vector<unsigned char> apps_permissions =
                            curr_obj_row[obj_cols.allows_apps_permissions];
                        int action_idx =
                            liststore_actions_public->get_path(iter)[0];
                        change_app_permission(app_name, apps_names, action_idx,
                                              state, apps_permissions);
                        curr_obj_row[obj_cols.allows_apps_names] = apps_names;
                        curr_obj_row[obj_cols.allows_apps_permissions] =
                            apps_permissions;
                        button_save_enable();
                    });
                Gtk::TreeViewColumn *treecolumn_toggle_public =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_toggle_public->pack_start(*renderer_toggle_public,
                                                     false);
                treecolumn_toggle_public->set_cell_data_func(
                    *renderer_toggle_public,
                    [&](const Gtk::CellRenderer *cellrenderer,
                        const Gtk::TreeModel::const_iterator &iter) {
                        auto cr = dynamic_cast<CellRendererThreeState *>(
                            const_cast<Gtk::CellRenderer *>(cellrenderer));
                        if (cr && iter) {
                            int state = (*iter)[action_cols.is_threestate];
                            cr->set_threestate(state);
                        }
                    });
                treeview_actions_public.set_model(public_filter_model);
                treeview_actions_public.append_column(
                    *treecolumn_toggle_public);
                Gtk::TreeViewColumn *treecolumn_icon_public =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                Gtk::CellRendererPixbuf *renderer_icon_public =
                    Gtk::make_managed<Gtk::CellRendererPixbuf>();
                treecolumn_icon_public->pack_start(*renderer_icon_public,
                                                   false);
                treecolumn_icon_public->add_attribute(
                    renderer_icon_public->property_pixbuf(), action_cols.icon);
                treeview_actions_public.append_column(*treecolumn_icon_public);
                CellRendererThreeStateGroup *renderer_toggle_public_group =
                    Gtk::make_managed<CellRendererThreeStateGroup>(
                        action_cols.is_threestate_group.index());
                treecolumn_toggle_public_group.pack_start(
                    *renderer_toggle_public_group, false);
                treecolumn_toggle_public_group.set_cell_data_func(
                    *renderer_toggle_public_group,
                    [&](const Gtk::CellRenderer *cellrenderer,
                        const Gtk::TreeModel::const_iterator &iter) {
                        auto cr = dynamic_cast<CellRendererThreeStateGroup *>(
                            const_cast<Gtk::CellRenderer *>(cellrenderer));
                        if (cr && iter) {
                            int state =
                                (*iter)[action_cols.is_threestate_group];
                            cr->set_threestate(state);
                        }
                    });
                treeview_actions_public.append_column(
                    treecolumn_toggle_public_group);
                Gtk::TreeViewColumn *treecolumn_description_public =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_description_public->set_title("Общие действия");
                treeview_actions_public.append_column(
                    *treecolumn_description_public);
                treecolumn_description_public->pack_start(
                    *renderer_toggle_public_group, false);
                Gtk::CellRendererText *renderer_description_public =
                    Gtk::make_managed<Gtk::CellRendererText>();
                treecolumn_description_public->pack_start(
                    *renderer_description_public, false);
                treecolumn_description_public->add_attribute(
                    renderer_description_public->property_text(),
                    action_cols.description);
                treeview_actions_public.get_selection()
                    ->signal_changed()
                    .connect([this]() {
                        treeview_actions_private.get_selection()
                            ->unselect_all();
                        Gtk::TreeModel::iterator iter =
                            treeview_actions_public.get_selection()
                                ->get_selected();
                        if (iter)
                            label_info.set_text(
                                (*iter)[action_cols.actionname]);
                    });
                auto add_public_action_row = [this](
                                                 std::string action_name,
                                                 std::string action_description,
                                                 std::string icon_name) {
                    Gtk::TreeModel::Row row =
                        *liststore_actions_public->append();
                    row[action_cols.icon] = Gdk::Pixbuf::create_from_resource(
                        std::string("/org/icons/apps/") + icon_name);
                    row[action_cols.actionname] = action_name;
                    row[action_cols.description] = action_description;
                    row[action_cols.is_visible] = false;
                };
                add_public_action_row("RunApplication", "Запуск приложения",
                                      "run.png");
                add_public_action_row("CloseApplication", "Закрытие приложения",
                                      "close.png");
                add_public_action_row("RunCopy", "Запуск копии приложения",
                                      "run-copy.png");
                add_public_action_row("WritePasports",
                                      "Запись значения в паспорт", "write.png");
                add_public_action_row("EditMode", "Режим редактирования",
                                      "edit.png");
                add_public_action_row("EditAdvancedMode",
                                      "Расширенный режим редактирования",
                                      "edit-advanced.png");

                treeview_actions_apps.get_selection()->signal_changed().connect(
                    [this]() { redraw_apps(); });

                private_filter_model =
                    Gtk::TreeModelFilter::create(liststore_actions_private);
                private_filter_model->set_visible_func(
                    [this](const Gtk::TreeModel::const_iterator &iter) -> bool {
                        if (!iter)
                            return false;
                        Gtk::TreeModel::Row row = *iter;
                        return row[action_cols.is_visible];
                    });
                CellRendererThreeState *renderer_toggle_private =
                    Gtk::make_managed<CellRendererThreeState>(
                        action_cols.is_threestate.index());
                renderer_toggle_private->signal_toggled().connect(
                    [this](const Glib::ustring &path) {
                        Gtk::TreeModel::Row curr_obj_row =
                            *treeview.get_selection()->get_selected();
                        Gtk::TreePath filtered_path(path);
                        Gtk::TreePath base_path =
                            private_filter_model->convert_path_to_child_path(
                                filtered_path);
                        Gtk::TreeModel::Row row =
                            *liststore_actions_private->get_iter(base_path);
                        if (!row)
                            return;
                        int state = row[action_cols.is_threestate];
                        state = (state + 1) % 3;
                        row[action_cols.is_threestate] = state;
                        Gtk::TreeModel::Row curr_app_row =
                            *treeview_actions_apps.get_selection()
                                 ->get_selected();
                        std::string app_name = static_cast<Glib::ustring>(
                            curr_app_row[action_cols.appname]);
                        std::vector<std::string> apps_names =
                            curr_obj_row[obj_cols.allows_apps_names];
                        std::vector<unsigned char> apps_permissions =
                            curr_obj_row[obj_cols.allows_apps_permissions];
                        change_app_permission(
                            app_name, apps_names,
                            static_cast<int>(row[action_cols.action_id]), state,
                            apps_permissions);
                        curr_obj_row[obj_cols.allows_apps_names] = apps_names;
                        curr_obj_row[obj_cols.allows_apps_permissions] =
                            apps_permissions;
                        button_save_enable();
                    });
                Gtk::TreeViewColumn *treecolumn_toggle_private =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_toggle_private->pack_start(*renderer_toggle_private,
                                                      true);
                treecolumn_toggle_private->set_cell_data_func(
                    *renderer_toggle_private,
                    [&](const Gtk::CellRenderer *cellrenderer,
                        const Gtk::TreeModel::const_iterator &iter) {
                        auto cr = dynamic_cast<CellRendererThreeState *>(
                            const_cast<Gtk::CellRenderer *>(cellrenderer));
                        if (cr && iter) {
                            int state_value =
                                (*iter)[action_cols.is_threestate];
                            cr->set_threestate(state_value);
                        }
                    });
                treeview_actions_private.set_model(private_filter_model);
                treeview_actions_private.append_column(
                    *treecolumn_toggle_private);
                Gtk::TreeViewColumn *treecolumn_icon_private =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                Gtk::CellRendererPixbuf *renderer_icon_private =
                    Gtk::make_managed<Gtk::CellRendererPixbuf>();
                treecolumn_icon_private->pack_start(*renderer_icon_private,
                                                    false);
                treecolumn_icon_private->add_attribute(
                    renderer_icon_private->property_pixbuf(), action_cols.icon);
                treeview_actions_private.append_column(
                    *treecolumn_icon_private);
                CellRendererThreeStateGroup *renderer_toggle_private_group =
                    Gtk::make_managed<CellRendererThreeStateGroup>(
                        action_cols.is_threestate_group.index());
                treecolumn_toggle_private_group.pack_start(
                    *renderer_toggle_private_group, false);
                treecolumn_toggle_private_group.set_cell_data_func(
                    *renderer_toggle_private_group,
                    [&](const Gtk::CellRenderer *cellrenderer,
                        const Gtk::TreeModel::const_iterator &iter) {
                        auto cr = dynamic_cast<CellRendererThreeStateGroup *>(
                            const_cast<Gtk::CellRenderer *>(cellrenderer));
                        if (cr && iter) {
                            int state =
                                (*iter)[action_cols.is_threestate_group];
                            cr->set_threestate(state);
                        }
                    });
                treeview_actions_private.append_column(
                    treecolumn_toggle_private_group);
                Gtk::TreeViewColumn *treecolumn_description_private =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treeview_actions_private.append_column(
                    *treecolumn_description_private);
                treecolumn_description_private->set_title("Приватные действия");
                Gtk::CellRendererText *renderer_description_private =
                    Gtk::make_managed<Gtk::CellRendererText>();
                treecolumn_description_private->pack_start(
                    *renderer_description_private, false);
                treecolumn_description_private->add_attribute(
                    renderer_description_private->property_text(),
                    action_cols.description);
                treeview_actions_private.get_selection()
                    ->signal_changed()
                    .connect([this]() {
                        treeview_actions_public.get_selection()->unselect_all();
                        Gtk::TreeModel::iterator iter =
                            treeview_actions_private.get_selection()
                                ->get_selected();
                        if (iter)
                            label_info.set_text(
                                (*iter)[action_cols.actionname]);
                    });
                treeview_actions_apps.get_selection()->select(
                    liststore_actions_apps->children().begin());

                stack_menu.add(*vbox_menu2);
                stack_menu.show_all();
                menus[1] = vbox_menu2;
            }
            treeview_actions_apps.get_selection()->select(
                liststore_actions_apps->children().begin());
            redraw_apps();

            stack_menu.set_visible_child(*menus[1]);
            curr_menu_idx = 1;
        }

        void redraw_zones_menu() {
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            unsigned char flags = curr_obj_row[obj_cols.flags];
            if ((flags & HAVE_ADMIN_RIGHTS) != 0) {
                stack_menu.set_visible_child(*menus[5]);
                curr_menu_idx = 2;
                return;
            }
            if (!menus[2]) {
                Gtk::Box *vbox_menu3 =
                    Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
                Gtk::Box *hbox_buttons =
                    Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_HORIZONTAL);
                set_margin(*hbox_buttons, 10, 10);
                vbox_menu3->pack_start(*hbox_buttons, Gtk::PACK_SHRINK);
                Gtk::Button *button_read_access =
                    Gtk::make_managed<Gtk::Button>("Доступ по чтению");
                hbox_buttons->pack_start(*button_read_access, Gtk::PACK_SHRINK);
                button_read_access->set_always_show_image(true);
                Glib::RefPtr<Gdk::Pixbuf> pixbuf_check_all =
                    Gdk::Pixbuf::create_from_resource(
                        "/org/icons/check-all.png");
                Gtk::Image *button_read_access_icon =
                    Gtk::make_managed<Gtk::Image>(pixbuf_check_all);
                button_read_access->set_image(*button_read_access_icon);
                button_read_access->signal_clicked().connect([this]() {
                    Gtk::TreeModel::Row curr_obj_row =
                        *treeview.get_selection()->get_selected();
                    Gtk::TreeModel::Row row =
                        *treeview_zones.get_selection()->get_selected();
                    bool curr_val = row[zone_cols.is_read_access];
                    row[zone_cols.is_read_access] = !curr_val;
                    if (!curr_val) {
                        row[zone_cols.is_full_access] = false;
                    }
                    Glib::ustring zone_name = row[zone_cols.zonename];
                    std::vector<std::string> zones_names =
                        curr_obj_row[obj_cols.allows_zones_names];
                    std::vector<unsigned char> zones_permissions =
                        curr_obj_row[obj_cols.allows_zones_permissions];
                    change_zone_permission(zone_name, zones_names,
                                           curr_val ? 0 : 1, zones_permissions);
                    curr_obj_row[obj_cols.allows_zones_names] = zones_names;
                    curr_obj_row[obj_cols.allows_zones_permissions] =
                        zones_permissions;
                    button_save_enable();
                });
                Gtk::Button *button_full_access =
                    Gtk::make_managed<Gtk::Button>("Полный доступ");
                hbox_buttons->pack_start(*button_full_access, Gtk::PACK_SHRINK);
                button_full_access->set_margin_left(5);
                button_full_access->set_always_show_image(true);
                Gtk::Image *button_full_access_icon =
                    Gtk::make_managed<Gtk::Image>(pixbuf_check_all);
                button_full_access->set_image(*button_full_access_icon);
                button_full_access->signal_clicked().connect([this]() {
                    Gtk::TreeModel::Row curr_obj_row =
                        *treeview.get_selection()->get_selected();
                    Gtk::TreeModel::Row row =
                        *treeview_zones.get_selection()->get_selected();
                    bool curr_val = row[zone_cols.is_full_access];
                    row[zone_cols.is_full_access] = !curr_val;
                    if (!curr_val) {
                        row[zone_cols.is_read_access] = false;
                    }
                    Glib::ustring zone_name = row[zone_cols.zonename];
                    std::vector<std::string> zones_names =
                        curr_obj_row[obj_cols.allows_zones_names];
                    std::vector<unsigned char> zones_permissions =
                        curr_obj_row[obj_cols.allows_zones_permissions];
                    change_zone_permission(zone_name, zones_names,
                                           curr_val ? 0 : 2, zones_permissions);
                    curr_obj_row[obj_cols.allows_zones_names] = zones_names;
                    curr_obj_row[obj_cols.allows_zones_permissions] =
                        zones_permissions;
                    button_save_enable();
                });

                Gtk::ScrolledWindow *scrolled_zones =
                    Gtk::make_managed<Gtk::ScrolledWindow>();
                scrolled_zones->set_name("white-background");
                scrolled_zones->set_policy(Gtk::POLICY_AUTOMATIC,
                                           Gtk::POLICY_AUTOMATIC);
                scrolled_zones->add(treeview_zones);
                Gtk::Frame *frame_zones = Gtk::make_managed<Gtk::Frame>();
                frame_zones->add(*scrolled_zones);
                vbox_menu3->pack_start(*frame_zones, true, true);
                set_margin(*frame_zones, 0, 10);
                set_margin(treeview_zones, 10, 10);

                Gtk::CellRendererPixbuf *renderer_icon =
                    Gtk::make_managed<Gtk::CellRendererPixbuf>();
                Gtk::TreeViewColumn *treecolumn_icon_name =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_icon_name->set_min_width(100);
                treecolumn_icon_name->set_title("Дерево параметров");
                treecolumn_icon_name->pack_start(*renderer_icon, false);
                treecolumn_icon_name->add_attribute(
                    renderer_icon->property_pixbuf(), zone_cols.icon);
                treeview_zones.set_model(treestore_zones);
                treeview_zones.append_column(*treecolumn_icon_name);
                Gtk::CellRendererText *renderer_name =
                    Gtk::make_managed<Gtk::CellRendererText>();
                treecolumn_icon_name->pack_start(*renderer_name, false);
                treecolumn_icon_name->add_attribute(
                    renderer_name->property_text(), zone_cols.zonename);
                Gtk::CellRendererToggle *renderer_toggle_read_access =
                    Gtk::make_managed<Gtk::CellRendererToggle>();
                renderer_toggle_read_access->property_xalign() = 0.0;
                Gtk::TreeViewColumn *treecolumn_toggle_read_access =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_toggle_read_access->set_min_width(100);
                treecolumn_toggle_read_access->set_title("Доступ по чтению");
                treecolumn_toggle_read_access->pack_start(
                    *renderer_toggle_read_access, Gtk::PACK_SHRINK);
                treecolumn_toggle_read_access->add_attribute(
                    renderer_toggle_read_access->property_active(),
                    zone_cols.is_read_access);
                renderer_toggle_read_access->signal_toggled().connect(
                    [this](const Glib::ustring &path) {
                        Gtk::TreeModel::Row curr_obj_row =
                            *treeview.get_selection()->get_selected();
                        Gtk::TreeModel::Row row =
                            *treestore_zones->get_iter(path);
                        bool curr_val = row[zone_cols.is_read_access];
                        row[zone_cols.is_read_access] = !curr_val;
                        if (!curr_val) {
                            row[zone_cols.is_full_access] = false;
                        }
                        Glib::ustring zone_name = row[zone_cols.zonename];
                        std::vector<std::string> zones_names =
                            curr_obj_row[obj_cols.allows_zones_names];
                        std::vector<unsigned char> zones_permissions =
                            curr_obj_row[obj_cols.allows_zones_permissions];
                        change_zone_permission(zone_name, zones_names,
                                               curr_val ? 0 : 1,
                                               zones_permissions);
                        curr_obj_row[obj_cols.allows_zones_names] = zones_names;
                        curr_obj_row[obj_cols.allows_zones_permissions] =
                            zones_permissions;
                        button_save_enable();
                    });
                treeview_zones.append_column(*treecolumn_toggle_read_access);
                Gtk::CellRendererToggle *renderer_toggle_full_access =
                    Gtk::make_managed<Gtk::CellRendererToggle>();
                renderer_toggle_full_access->property_xalign() = 0.0;
                Gtk::TreeViewColumn *treecolumn_toggle_full_access =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_toggle_full_access->set_min_width(100);
                treecolumn_toggle_full_access->set_title("Полный доступ");
                treecolumn_toggle_full_access->pack_start(
                    *renderer_toggle_full_access, Gtk::PACK_SHRINK);
                treecolumn_toggle_full_access->add_attribute(
                    renderer_toggle_full_access->property_active(),
                    zone_cols.is_full_access);
                renderer_toggle_full_access->signal_toggled().connect(
                    [this](const Glib::ustring &path) {
                        Gtk::TreeModel::Row curr_obj_row =
                            *treeview.get_selection()->get_selected();
                        Gtk::TreeModel::Row row =
                            *treestore_zones->get_iter(path);
                        bool curr_val = row[zone_cols.is_full_access];
                        row[zone_cols.is_full_access] = !curr_val;
                        if (!curr_val) {
                            row[zone_cols.is_read_access] = false;
                        }
                        Glib::ustring zone_name = row[zone_cols.zonename];
                        std::vector<std::string> zones_names =
                            curr_obj_row[obj_cols.allows_zones_names];
                        std::vector<unsigned char> zones_permissions =
                            curr_obj_row[obj_cols.allows_zones_permissions];
                        change_zone_permission(zone_name, zones_names,
                                               curr_val ? 0 : 2,
                                               zones_permissions);
                        curr_obj_row[obj_cols.allows_zones_names] = zones_names;
                        curr_obj_row[obj_cols.allows_zones_permissions] =
                            zones_permissions;
                        button_save_enable();
                    });
                treeview_zones.append_column(*treecolumn_toggle_full_access);
                Gtk::CellRendererToggle *renderer_toggle_exclusive_access =
                    Gtk::make_managed<Gtk::CellRendererToggle>();
                renderer_toggle_exclusive_access->property_xalign() = 0.0;
                Gtk::TreeViewColumn *treecolumn_toggle_exclusive_access =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_toggle_exclusive_access->set_min_width(100);
                treecolumn_toggle_exclusive_access->set_title(
                    "Монопольный доступ");
                treecolumn_toggle_exclusive_access->pack_start(
                    *renderer_toggle_exclusive_access, Gtk::PACK_SHRINK);
                treecolumn_toggle_exclusive_access->add_attribute(
                    renderer_toggle_exclusive_access->property_active(),
                    zone_cols.is_exclusive_access);
                renderer_toggle_exclusive_access->signal_toggled().connect(
                    [this](const Glib::ustring &path) {
                        Gtk::TreeModel::iterator iter =
                            treestore_zones->get_iter(path);
                        if (iter) {
                            bool curr_val =
                                (*iter)[zone_cols.is_exclusive_access];
                            (*iter)[zone_cols.is_exclusive_access] = !curr_val;
                        }
                    });
                treeview_zones.append_column(
                    *treecolumn_toggle_exclusive_access);
                stack_menu.add(*vbox_menu3);
                stack_menu.show_all();
                menus[2] = vbox_menu3;
            }
            treeview_zones.get_selection()->select(
                treestore_zones->children().begin());
            redraw_zones();

            stack_menu.set_visible_child(*menus[2]);
            curr_menu_idx = 2;
        }

        void redraw_statistics_menu() {
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            Glib::ustring username = curr_obj_row[obj_cols.username];
            if (username.empty()) {
                return;
            }
            if (!menus[3]) {
                Gtk::Box *vbox_menu4 =
                    Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
                Gtk::Frame *frame_statistics = Gtk::make_managed<Gtk::Frame>();
                Gtk::Label *label_statistics =
                    Gtk::make_managed<Gtk::Label>("Статистика пользователя");
                frame_statistics->set_label_widget(*label_statistics);
                vbox_menu4->pack_start(*frame_statistics, Gtk::PACK_SHRINK);
                Gtk::Box *vbox_statistics =
                    Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL, 10);
                set_margin(*vbox_statistics, 10, 10);
                frame_statistics->add(*vbox_statistics);
                frame_statistics->set_margin_top(5);

                auto add_row = [this](const std::string &title,
                                      Gtk::Entry *entry, Gtk::Box *box) {
                    auto hbox = Gtk::make_managed<Gtk::Box>(
                        Gtk::ORIENTATION_HORIZONTAL, 5);
                    auto label = Gtk::make_managed<Gtk::Label>(title);
                    hbox->pack_start(*label, Gtk::PACK_SHRINK);
                    hbox->pack_start(*entry, Gtk::PACK_EXPAND_WIDGET);
                    set_margin(*entry, 5, 5);
                    box->pack_start(*hbox, Gtk::PACK_SHRINK);
                };
                entry_statistics_registration_date =
                    Gtk::make_managed<Gtk::Entry>();
                entry_statistics_registration_date->set_editable(false);
                entry_statistics_registration_date->set_can_focus(false);
                entry_statistics_last_login_date =
                    Gtk::make_managed<Gtk::Entry>();
                entry_statistics_last_login_date->set_editable(false);
                entry_statistics_last_login_date->set_can_focus(false);
                entry_statistics_last_password_change_date =
                    Gtk::make_managed<Gtk::Entry>();
                entry_statistics_last_password_change_date->set_editable(false);
                entry_statistics_last_password_change_date->set_can_focus(
                    false);
                entry_statistics_password_expiration_date =
                    Gtk::make_managed<Gtk::Entry>();
                entry_statistics_password_expiration_date->set_editable(false);
                entry_statistics_password_expiration_date->set_can_focus(false);
                add_row("Дата и время регистрации:",
                        entry_statistics_registration_date, vbox_statistics);
                add_row("Дата и время\n последнего входа в систему:",
                        entry_statistics_last_login_date, vbox_statistics);
                add_row("Дата и время\n последней смены пароля:",
                        entry_statistics_last_password_change_date,
                        vbox_statistics);
                add_row("Дата и время\n истечения срока действия пароля:",
                        entry_statistics_password_expiration_date,
                        vbox_statistics);

                stack_menu.add(*vbox_menu4);
                stack_menu.show_all();
                menus[3] = vbox_menu4;
            }
            Glib::ustring registration_dt_str =
                curr_obj_row[obj_cols.registertime];
            Glib::DateTime registration_dt =
                parse_datetime(registration_dt_str);
            entry_statistics_registration_date->set_text(
                format_datetime(registration_dt));
            Glib::ustring last_pwd_change_dt_str =
                curr_obj_row[obj_cols.lastpwdchangetime];
            Glib::DateTime last_pwd_change_dt =
                parse_datetime(last_pwd_change_dt_str);
            entry_statistics_last_password_change_date->set_text(
                format_datetime(last_pwd_change_dt));
            int pwd_keep_period = curr_obj_row[obj_cols.pwdkeepperiod];
            if (pwd_keep_period == 0) {
                entry_statistics_password_expiration_date->set_text("Никогда");
            } else {
                Glib::DateTime pwd_expiration_dt =
                    last_pwd_change_dt.add_days(pwd_keep_period);
                entry_statistics_password_expiration_date->set_text(
                    format_datetime(pwd_expiration_dt));
            }
            Glib::ustring last_login_dt_str =
                curr_obj_row[obj_cols.lastentertime];
            Glib::DateTime last_login_dt = parse_datetime(last_login_dt_str);
            entry_statistics_last_login_date->set_text(
                format_datetime(last_login_dt));

            stack_menu.set_visible_child(*menus[3]);
            curr_menu_idx = 3;
        }

        void redraw_arms_menu() {
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            unsigned char flags = curr_obj_row[obj_cols.flags];
            if ((flags & HAVE_ADMIN_RIGHTS) != 0) {
                stack_menu.set_visible_child(*menus[5]);
                curr_menu_idx = 4;
                return;
            }
            if (!menus[4]) {
                Gtk::Box *vbox_menu5 =
                    Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
                Gtk::ScrolledWindow *scrolled_arms =
                    Gtk::make_managed<Gtk::ScrolledWindow>();
                scrolled_arms->set_name("white-background");
                scrolled_arms->set_policy(Gtk::POLICY_AUTOMATIC,
                                          Gtk::POLICY_AUTOMATIC);
                scrolled_arms->add(treeview_arms);
                vbox_menu5->pack_start(*scrolled_arms, true, true);
                set_margin(treeview_arms, 10, 10);
                scrolled_arms->set_margin_top(10);

                Gtk::CellRendererText *renderer_id =
                    Gtk::make_managed<Gtk::CellRendererText>();
                Gtk::TreeViewColumn *treecolumn_id =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_id->set_min_width(100);
                treecolumn_id->set_title("ID");
                treecolumn_id->pack_start(*renderer_id, false);
                treecolumn_id->add_attribute(renderer_id->property_text(),
                                             arm_cols.id);
                liststore_arms = Gtk::ListStore::create(arm_cols);
                treeview_arms.set_model(liststore_arms);
                treeview_arms.append_column(*treecolumn_id);
                Gtk::CellRendererText *renderer_toy =
                    Gtk::make_managed<Gtk::CellRendererText>();
                Gtk::TreeViewColumn *treecolumn_toy =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_toy->set_min_width(100);
                treecolumn_toy->set_title("ТОУ");
                treecolumn_toy->pack_start(*renderer_toy, false);
                treecolumn_toy->add_attribute(renderer_toy->property_text(),
                                              arm_cols.toy);
                treeview_arms.append_column(*treecolumn_toy);
                Gtk::CellRendererText *renderer_arm =
                    Gtk::make_managed<Gtk::CellRendererText>();
                Gtk::TreeViewColumn *treecolumn_arm =
                    Gtk::make_managed<Gtk::TreeViewColumn>();
                treecolumn_arm->set_min_width(100);
                treecolumn_arm->set_title("АРМ");
                treecolumn_arm->pack_start(*renderer_arm, false);
                treecolumn_arm->add_attribute(renderer_arm->property_text(),
                                              arm_cols.arm);
                treeview_arms.append_column(*treecolumn_arm);

                stack_menu.add(*vbox_menu5);
                stack_menu.show_all();
                menus[4] = vbox_menu5;
            }

            stack_menu.set_visible_child(*menus[4]);
            curr_menu_idx = 4;
        }

        void redraw_apps() {
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            Gtk::TreeModel::Row curr_app_row =
                *treeview_actions_apps.get_selection()->get_selected();
            if (!curr_app_row) {
                if (!liststore_actions_apps->children())
                    return;
                curr_app_row = *liststore_actions_apps->children().begin();
                treeview_actions_apps.get_selection()->select(curr_app_row);
            }
            Glib::ustring curr_app_name = curr_app_row[action_cols.appname];
            label_info.set_text(curr_app_row[action_cols.appname]);

            // Обновление приложений в меню действий
            Glib::ustring username = curr_obj_row[obj_cols.username];
            std::string group_name =
                static_cast<Glib::ustring>(curr_obj_row[obj_cols.grpname]);
            if (username.empty() || group_name.empty()) {
                treecolumn_toggle_apps_group.set_visible(false);
                treecolumn_toggle_public_group.set_visible(false);
                treecolumn_toggle_private_group.set_visible(false);
            } else {
                treecolumn_toggle_apps_group.set_visible(true);
                treecolumn_toggle_public_group.set_visible(true);
                treecolumn_toggle_private_group.set_visible(true);
            }
            std::vector<std::string> apps_names =
                curr_obj_row[obj_cols.allows_apps_names];
            Gtk::TreeModel::iterator group_iter =
                get_by_name(group_name, treestore_objs, obj_cols, false);
            std::vector<std::string> group_apps_names;
            std::vector<bool> group_apps_enabled;
            std::vector<unsigned char> group_apps_permissions;
            if (group_iter) {
                group_apps_names = (*group_iter)[obj_cols.allows_apps_names];
                group_apps_enabled =
                    (*group_iter)[obj_cols.allows_apps_enabled];
                group_apps_permissions =
                    (*group_iter)[obj_cols.allows_apps_permissions];
            }
            bool has_group_apps = group_apps_names.size() > 0;
            for (const Gtk::TreeModel::Row &app_row :
                 liststore_actions_apps->children()) {
                if (has_group_apps) {
                    Glib::ustring app_name = (*app_row)[action_cols.appname];
                    auto group_app_vec_iter =
                        std::find(group_apps_names.begin(),
                                  group_apps_names.end(), app_name);
                    if (group_app_vec_iter == group_apps_names.end()) {
                        app_row[action_cols.is_enabled_group] = false;
                        continue;
                    }
                    int group_app_idx = std::distance(group_apps_names.begin(),
                                                      group_app_vec_iter);
                    bool at_least_one_permission = std::any_of(
                        group_apps_permissions.begin() + 25 * group_app_idx,
                        group_apps_permissions.begin() + 25 * group_app_idx +
                            25,
                        [](int permission) {
                            return permission == 1 || permission == 2;
                        });
                    app_row[action_cols.is_enabled_group] =
                        group_apps_enabled[group_app_idx] &&
                        at_least_one_permission;
                } else {
                    app_row[action_cols.is_enabled_group] = false;
                }
            }
            std::vector<unsigned char> apps_permissions =
                curr_obj_row[obj_cols.allows_apps_permissions];
            std::vector<bool> apps_enabled =
                curr_obj_row[obj_cols.allows_apps_enabled];
            Gtk::TreeModel::Children apps = liststore_actions_apps->children();
            for (Gtk::TreeModel::iterator app_iter = apps.begin();
                 app_iter != apps.end(); ++app_iter) {
                Gtk::TreeModel::Row app_row = *app_iter;
                auto app_vec_iter = std::find(
                    apps_names.begin(), apps_names.end(),
                    static_cast<Glib::ustring>(app_row[action_cols.appname]));
                if (app_vec_iter == apps_names.end()) {
                    app_row[action_cols.is_enabled] = false;
                    continue;
                }
                int app_idx = std::distance(apps_names.begin(), app_vec_iter);
                bool at_least_one_permission =
                    std::any_of(apps_permissions.begin() + 25 * app_idx,
                                apps_permissions.begin() + 25 * app_idx + 25,
                                [](int permission) {
                                    return permission == 1 || permission == 2;
                                });
                bool curr_val = app_row[action_cols.is_enabled];
                app_row[action_cols.is_enabled] =
                    (((app_row == curr_app_row) &&
                      (curr_app_row != stored_prev_app_row)) &&
                     curr_val) ||
                    (apps_enabled[app_idx] && at_least_one_permission);
            }
            stored_prev_app_row = curr_app_row;

            // Обновление публичных действий в меню действий
            bool has_group_permissions = group_apps_permissions.size() > 0;
            std::vector<unsigned char> group_app_permissions;
            if (has_group_permissions)
                group_app_permissions = get_app_permissions(
                    curr_app_name, group_apps_names, group_apps_permissions);
            std::vector<unsigned char> app_permissions = get_app_permissions(
                curr_app_name, apps_names, apps_permissions);
            Glib::ustring app_globactmask =
                curr_app_row[action_cols.globactmask];
            int public_action_idx = 0;
            for (const Gtk::TreeModel::Row &public_action_row :
                 liststore_actions_public->children()) {
                Glib::ustring app_name = public_action_row[action_cols.appname];
                public_action_row[action_cols.is_threestate] =
                    app_permissions[public_action_idx];
                if (has_group_permissions) {
                    public_action_row[action_cols.is_threestate_group] =
                        group_app_permissions[public_action_idx];
                } else {
                    public_action_row[action_cols.is_threestate_group] = 0;
                }
                public_action_row[action_cols.is_visible] =
                    app_globactmask[public_action_idx] == '0';
                public_action_idx++;
            }
            public_filter_model->refilter();

            // Обновление приватных действий в меню действий
            for (const Gtk::TreeModel::Row &private_action_row :
                 liststore_actions_private->children()) {
                Glib::ustring app_name =
                    private_action_row[action_cols.appname];
                if (curr_app_row[action_cols.appname] ==
                    private_action_row[action_cols.appname]) {
                    private_action_row[action_cols.is_visible] = true;
                    private_action_row[action_cols.is_threestate] =
                        app_permissions[static_cast<int>(
                            private_action_row[action_cols.action_id])];
                    if (has_group_permissions) {
                        private_action_row[action_cols.is_threestate_group] =
                            group_app_permissions[static_cast<int>(
                                private_action_row[action_cols.action_id])];
                    } else {
                        private_action_row[action_cols.is_threestate_group] = 0;
                    }
                } else {
                    private_action_row[action_cols.is_visible] = false;
                }
            }
            private_filter_model->refilter();

            if (!curr_app_row[action_cols.is_enabled]) {
                treeview_actions_public.set_sensitive(false);
                treeview_actions_private.set_sensitive(false);
                treeview_actions_public.get_selection()->unselect_all();
                treeview_actions_private.get_selection()->unselect_all();
            } else {
                treeview_actions_public.set_sensitive(true);
                treeview_actions_private.set_sensitive(true);
            }
        }

        void redraw_zones() {
            Gtk::TreeModel::Row curr_obj_row =
                *treeview.get_selection()->get_selected();
            Gtk::TreeModel::Row curr_zone_row =
                *treeview_zones.get_selection()->get_selected();
            if (!curr_zone_row) {
                curr_zone_row = *treestore_zones->children().begin();
                treeview_zones.get_selection()->select(curr_zone_row);
            }
            Glib::ustring curr_zone_name = curr_zone_row[zone_cols.zonename];
            label_info.set_text(curr_zone_row[zone_cols.zonename]);

            // Обновление чекбоксов дерева зон
            std::string group_name =
                static_cast<Glib::ustring>(curr_obj_row[obj_cols.grpname]);
            Gtk::TreeModel::iterator group_iter;
            if (group_name.empty()) {
                treeview_zones.set_sensitive(true);
            } else {
                group_iter =
                    get_by_name(group_name, treestore_objs, obj_cols, false);
                treeview_zones.get_selection()->unselect_all();
                treeview_zones.set_sensitive(false);
            }
            std::vector<std::string> zones_names =
                (group_name.empty() ? curr_obj_row
                                    : *group_iter)[obj_cols.allows_zones_names];
            std::vector<unsigned char> zones_permissions =
                (group_name.empty()
                     ? *curr_obj_row
                     : *group_iter)[obj_cols.allows_zones_permissions];
            for (const Gtk::TreeModel::Row &zone_row :
                 treestore_zones->children()) {
                Glib::ustring zone_name = zone_row[zone_cols.zonename];
                auto zone_vec_iter = std::find(zones_names.begin(),
                                               zones_names.end(), zone_name);
                unsigned char zone_permission = 0;
                if (zone_vec_iter != zones_names.end()) {
                    int zone_name_idx =
                        std::distance(zones_names.begin(), zone_vec_iter);
                    zone_permission = zones_permissions[zone_name_idx];
                }
                switch (zone_permission) {
                case 0:
                    zone_row[zone_cols.is_read_access] = false;
                    zone_row[zone_cols.is_full_access] = false;
                    break;
                case 1:
                    zone_row[zone_cols.is_read_access] = true;
                    zone_row[zone_cols.is_full_access] = false;
                    break;
                case 2:
                    zone_row[zone_cols.is_read_access] = false;
                    zone_row[zone_cols.is_full_access] = true;
                    break;
                }
            }
        }

    private:
        void setup_ui() {
            set_title("Настройка прав пользователей");
            auto css = Gtk::CssProvider::create();
            css->load_from_data(R"(
                * {
                    font-family: Sans;
                    font-size: 14px;
                }
                #read-only {
                    opacity: 0.75;
                }
                #button-without-border {
                    border-style: none;
                    background-color: transparent;
                }
                #white-background {
                    background-image: none;
                    background-color: white;
                }
            )");
            auto screen = get_screen();
            Gtk::StyleContext::add_provider_for_screen(
                screen, css, GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

            set_titlebar(header_bar);
            header_bar.set_show_close_button(true);
            header_bar.set_decoration_layout("menu:minimize,maximize,close");
            add(vbox_main);
            hbox_form_buttons_bar.set_margin_bottom(5);

            vbox_main.set_hexpand(true);
            vbox_main.set_vexpand(true);
            scrolled_tree_objs.set_name("white-background");
            scrolled_tree_objs.set_hexpand(true);
            scrolled_tree_objs.set_vexpand(true);
            scrolled_tree_objs.set_min_content_height(600);
            scrolled_tree_objs.set_min_content_width(TREE_MIN_WIDTH);
            treeview.set_hexpand(true);
            treeview.set_vexpand(true);
            scrolled_form_objs.set_hexpand(true);
            scrolled_form_objs.set_vexpand(true);
            scrolled_form_objs.set_min_content_height(600);
            scrolled_form_objs.set_min_content_width(FORM_MIN_WIDTH);
            combobox_properties_group.set_name("read-only");
            vbox_form.set_hexpand(true);
            vbox_form.set_vexpand(true);

            vbox_main.pack_start(paned_main, Gtk::PACK_EXPAND_WIDGET);
            paned_main.set_hexpand(true);
            paned_main.add1(frame_tree_objs);
            set_margin(frame_tree_objs, 10, 10);
            set_margin(treeview, 10, 10);
            frame_tree_objs.add(scrolled_tree_objs);
            paned_main.child_property_resize(frame_tree_objs) = true;
            paned_main.child_property_shrink(frame_tree_objs) = true;
            scrolled_tree_objs.set_policy(Gtk::POLICY_AUTOMATIC,
                                          Gtk::POLICY_AUTOMATIC);
            scrolled_tree_objs.add(treeview);
            treeview.set_model(treestore_objs);
            treeview.set_headers_visible(false);
            renderer_icon.set_alignment(0.0, 0.0);
            treecolumn_icon_name.pack_start(renderer_icon, false);
            treecolumn_icon_name.add_attribute(renderer_icon.property_pixbuf(),
                                               obj_cols.icon);
            treecolumn_icon_name.pack_start(renderer_name, false);
            treecolumn_icon_name.add_attribute(renderer_name.property_text(),
                                               obj_cols.name);
            treeview.append_column(treecolumn_icon_name);

            paned_main.add2(scrolled_form_objs);
            paned_main.child_property_resize(scrolled_form_objs) = true;
            paned_main.child_property_shrink(scrolled_form_objs) = true;
            scrolled_form_objs.add(vbox_form);
            scrolled_form_objs.set_policy(Gtk::POLICY_AUTOMATIC,
                                          Gtk::POLICY_AUTOMATIC);

            vbox_form.pack_start(hbox_form_buttons_bar, Gtk::PACK_SHRINK);
            vbox_form.pack_start(frame_stack_menu, Gtk::PACK_EXPAND_WIDGET);
            frame_stack_menu.set_name("white-background");
            frame_stack_menu.add(stack_menu);
            set_margin(stack_menu, 10, 10);

            label_info.set_halign(Gtk::ALIGN_START);
            vbox_main.pack_start(label_info, Gtk::PACK_SHRINK);
        }

        void setup_gresources() {
            pixbuf_save_enabled = Gdk::Pixbuf::create_from_resource(
                "/org/icons/save-enabled.png");
            pixbuf_new_group =
                Gdk::Pixbuf::create_from_resource("/org/icons/group-add.png");
            pixbuf_new_user =
                Gdk::Pixbuf::create_from_resource("/org/icons/user-add.png");
            pixbuf_user =
                Gdk::Pixbuf::create_from_resource("/org/icons/user.png");
            pixbuf_group =
                Gdk::Pixbuf::create_from_resource("/org/icons/group.png");
            pixbuf_admin =
                Gdk::Pixbuf::create_from_resource("/org/icons/admin.png");
            pixbuf_delete =
                Gdk::Pixbuf::create_from_resource("/org/icons/delete.png");
            pixbuf_settings =
                Gdk::Pixbuf::create_from_resource("/org/icons/settings.png");
            pixbuf_help = Gdk::Pixbuf::create_from_resource(
                "/org/icons/question-mark.png");
            pixbuf_save_disabled = Gdk::Pixbuf::create_from_resource(
                "/org/icons/save-disabled.png");
        }

        void setup_menubuttons() {
            menubutton_file.set_label("Файл");
            menubutton_file.set_name("button-without-border");
            menubutton_file.set_relief(Gtk::RELIEF_NONE);
            header_bar.pack_start(menubutton_file);
            menu_file.append(menuitem_save);
            menuitem_save.add(menuitem_save_box);
            menuitem_save_box.pack_start(menuitem_save_icon, Gtk::PACK_SHRINK);
            menuitem_save_box.pack_start(menuitem_save_label, Gtk::PACK_SHRINK);
            menu_file.append(menuitem_exit);
            menuitem_exit.add(menuitem_exit_box);
            menuitem_exit_box.pack_start(menuitem_exit_label, Gtk::PACK_SHRINK);
            menubutton_file.set_popup(menu_file);
            menu_file.show_all();

            menuitem_new_group_icon = Gtk::Image(pixbuf_new_group);
            menubutton_users.set_label("Пользователи");
            menubutton_users.set_name("button-without-border");
            menubutton_users.set_relief(Gtk::RELIEF_NONE);
            header_bar.pack_start(menubutton_users);
            menu_users.append(menuitem_new_group);
            menuitem_new_group.add(menuitem_new_group_box);
            menuitem_new_group_box.pack_start(menuitem_new_group_icon,
                                              Gtk::PACK_SHRINK);
            menuitem_new_group_box.pack_start(menuitem_new_group_label,
                                              Gtk::PACK_SHRINK);
            menuitem_new_user_icon = Gtk::Image(pixbuf_new_user);
            menu_users.append(menuitem_new_user);
            menuitem_new_user.add(menuitem_new_user_box);
            menuitem_new_user_box.pack_start(menuitem_new_user_icon,
                                             Gtk::PACK_SHRINK);
            menuitem_new_user_box.pack_start(menuitem_new_user_label,
                                             Gtk::PACK_SHRINK);
            menuitem_delete_icon = Gtk::Image(pixbuf_delete);
            menu_users.append(menuitem_delete);
            menuitem_delete.add(menuitem_delete_box);
            menuitem_delete_box.pack_start(menuitem_delete_icon,
                                           Gtk::PACK_SHRINK);
            menuitem_delete_box.pack_start(menuitem_delete_label,
                                           Gtk::PACK_SHRINK);
            menubutton_users.set_popup(menu_users);
            menu_users.show_all();

            menuitem_settings_icon = Gtk::Image(pixbuf_settings);
            menubutton_service.set_label("Сервис");
            menubutton_service.set_name("button-without-border");
            menubutton_service.set_relief(Gtk::RELIEF_NONE);
            header_bar.pack_start(menubutton_service);
            menu_service.append(menuitem_settings);
            menuitem_settings.add(menuitem_settings_box);
            menuitem_settings_box.pack_start(menuitem_settings_icon,
                                             Gtk::PACK_SHRINK);
            menuitem_settings_box.pack_start(menuitem_settings_label,
                                             Gtk::PACK_SHRINK);
            menubutton_service.set_popup(menu_service);
            menu_service.show_all();

            menuitem_help_icon = Gtk::Image(pixbuf_help);
            menubutton_help.set_label("Справка");
            menubutton_help.set_name("button-without-border");
            menubutton_help.set_relief(Gtk::RELIEF_NONE);
            header_bar.pack_start(menubutton_help);
            menu_help.append(menuitem_help);
            menuitem_help.add(menuitem_help_box);
            menuitem_help_box.pack_start(menuitem_help_icon, Gtk::PACK_SHRINK);
            menuitem_help_box.pack_start(menuitem_help_label, Gtk::PACK_SHRINK);
            menubutton_help.set_popup(menu_help);
            menu_help.show_all();
        }

        void setup_top_bar() {
            vbox_main.pack_start(top_bar, Gtk::PACK_SHRINK);
            top_bar.pack_start(button_save, Gtk::PACK_SHRINK);

            button_save.set_tooltip_text("Сохранить (Ctrl+S)");
            button_save.set_image(button_save_icon);
            button_save.set_always_show_image(true);
            button_save_disable();
            top_bar.pack_start(top_bar_separator1, Gtk::PACK_SHRINK);

            button_new_group_icon = Gtk::Image(pixbuf_new_group);
            top_bar.pack_start(button_new_group, Gtk::PACK_SHRINK);
            button_new_group.set_tooltip_text("Добавить группу");
            button_new_group.set_image(button_new_group_icon);
            button_new_group.set_always_show_image(true);

            button_new_user_icon = Gtk::Image(pixbuf_new_user);
            top_bar.pack_start(button_new_user, Gtk::PACK_SHRINK);
            button_new_user.set_tooltip_text("Добавить пользователя");
            button_new_user.set_image(button_new_user_icon);
            button_new_user.set_always_show_image(true);
            top_bar.pack_start(top_bar_separator2, Gtk::PACK_SHRINK);

            button_delete_icon = Gtk::Image(pixbuf_delete);
            top_bar.pack_start(button_delete, Gtk::PACK_SHRINK);
            button_delete.set_tooltip_text("Удалить");
            button_delete.set_image(button_delete_icon);
            button_delete.set_always_show_image(true);
            button_delete.set_sensitive(false);
            top_bar.pack_start(top_bar_separator3, Gtk::PACK_SHRINK);

            button_settings_icon = Gtk::Image(pixbuf_settings);
            top_bar.pack_start(button_settings, Gtk::PACK_SHRINK);
            button_settings.set_tooltip_text("Настройки");
            button_settings.set_image(button_settings_icon);
            button_settings.set_always_show_image(true);

            set_margin(top_bar, 0, 5);
            set_margin(scrolled_form_objs, 10, 10);
            set_margin(treeview, 10, 10);
            button_save.set_margin_left(5);
        }

        void setup_menus() {
            // Настройка кнопок вызова меню
            menus = std::vector<Gtk::Box *>(6, nullptr);
            Gtk::RadioButton *radiobutton_properties_menu =
                Gtk::make_managed<Gtk::RadioButton>(radiogroup_menu,
                                                    "Свойства");
            hbox_form_buttons_bar.pack_start(*radiobutton_properties_menu,
                                             Gtk::PACK_SHRINK);
            radiobutton_properties_menu->set_mode(false);
            radiobuttons_form_buttons_bar.push_back(
                radiobutton_properties_menu);
            radiobutton_properties_menu->signal_toggled().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::redraw_properties_menu));
            Gtk::RadioButton *radiobutton_actions_menu =
                Gtk::make_managed<Gtk::RadioButton>(radiogroup_menu,
                                                    "Действия");
            hbox_form_buttons_bar.pack_start(*radiobutton_actions_menu,
                                             Gtk::PACK_SHRINK);
            radiobutton_actions_menu->set_mode(false);
            radiobuttons_form_buttons_bar.push_back(radiobutton_actions_menu);
            radiobutton_actions_menu->signal_toggled().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::redraw_actions_menu));
            Gtk::RadioButton *radiobutton_zones_menu =
                Gtk::make_managed<Gtk::RadioButton>(radiogroup_menu, "Зоны");
            hbox_form_buttons_bar.pack_start(*radiobutton_zones_menu,
                                             Gtk::PACK_SHRINK);
            radiobutton_zones_menu->set_mode(false);
            radiobuttons_form_buttons_bar.push_back(radiobutton_zones_menu);
            radiobutton_zones_menu->signal_toggled().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::redraw_zones_menu));
            Gtk::RadioButton *radiobutton_statistics_menu =
                Gtk::make_managed<Gtk::RadioButton>(radiogroup_menu,
                                                    "Статистика");
            hbox_form_buttons_bar.pack_start(*radiobutton_statistics_menu,
                                             Gtk::PACK_SHRINK);
            radiobutton_statistics_menu->set_mode(false);
            radiobuttons_form_buttons_bar.push_back(
                radiobutton_statistics_menu);
            radiobutton_statistics_menu->signal_toggled().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::redraw_statistics_menu));
            Gtk::RadioButton *radiobutton_arms_menu =
                Gtk::make_managed<Gtk::RadioButton>(radiogroup_menu, "АРМы");
            hbox_form_buttons_bar.pack_start(*radiobutton_arms_menu,
                                             Gtk::PACK_SHRINK);
            radiobutton_arms_menu->set_mode(false);
            radiobuttons_form_buttons_bar.push_back(radiobutton_arms_menu);
            radiobutton_arms_menu->signal_toggled().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::redraw_arms_menu));

            // Создание меню свойств
            Gtk::Box *vbox_properties_menu =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL);
            Gtk::Frame *frame_group = Gtk::make_managed<Gtk::Frame>();
            frame_group->set_label_widget(label_properties_is_group);
            vbox_properties_menu->pack_start(*frame_group, Gtk::PACK_SHRINK);
            Gtk::Box *vbox_group =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL, 10);
            set_margin(*vbox_group, 10, 10);
            frame_group->add(*vbox_group);
            Gtk::Box *hbox_group_name =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_HORIZONTAL, 10);
            hbox_group_name->pack_start(entry_properties_name,
                                        Gtk::PACK_EXPAND_WIDGET);
            hbox_group_name->pack_start(button_properties_apply_name,
                                        Gtk::PACK_SHRINK);
            vbox_group->pack_start(*hbox_group_name, Gtk::PACK_SHRINK);
            Gtk::Grid *grid_group = Gtk::make_managed<Gtk::Grid>();
            grid_group->set_column_spacing(25);
            grid_group->set_row_spacing(5);
            vbox_group->pack_start(*grid_group, Gtk::PACK_EXPAND_WIDGET);
            Gtk::Label *label_description =
                Gtk::make_managed<Gtk::Label>("Описание");
            grid_group->attach(*label_description, 0, 0, 1, 1);
            grid_group->attach(entry_properties_extrainfo, 1, 0, 1, 1);
            entry_properties_extrainfo.set_halign(Gtk::ALIGN_FILL);
            entry_properties_extrainfo.set_hexpand(true);
            grid_group->attach(label_properties_group, 0, 1, 1, 1);
            label_properties_group.set_halign(Gtk::ALIGN_START);
            grid_group->attach(combobox_properties_group, 1, 1, 1, 1);
            combobox_properties_group.set_sensitive(false);

            Gtk::Frame *frame_unnamed = Gtk::make_managed<Gtk::Frame>();
            vbox_properties_menu->pack_start(*frame_unnamed, Gtk::PACK_SHRINK);
            Gtk::Box *vbox_unnamed =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL, 10);
            set_margin(*vbox_unnamed, 10, 10);
            frame_unnamed->add(*vbox_unnamed);
            vbox_unnamed->pack_start(checkbutton_assign_admin_rights,
                                     Gtk::PACK_SHRINK);
            vbox_unnamed->pack_start(checkbutton_allow_password_change,
                                     Gtk::PACK_SHRINK);
            vbox_unnamed->pack_start(checkbutton_allow_to_set_as_default_user,
                                     Gtk::PACK_SHRINK);
            vbox_unnamed->pack_start(
                checkbutton_require_password_change_on_next_login,
                Gtk::PACK_SHRINK);
            vbox_unnamed->pack_start(checkbutton_set_as_default_user,
                                     Gtk::PACK_SHRINK);
            Gtk::Box *hbox_unnamed_default_arm =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_HORIZONTAL, 10);
            vbox_unnamed->pack_start(*hbox_unnamed_default_arm,
                                     Gtk::PACK_SHRINK);
            hbox_unnamed_default_arm->pack_start(label_properties_default_arm,
                                                 Gtk::PACK_SHRINK);
            hbox_unnamed_default_arm->pack_start(combobox_properties_arms,
                                                 Gtk::PACK_EXPAND_WIDGET);
            Gtk::Box *hbox_unnamed_password_expiration =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_HORIZONTAL, 10);
            vbox_unnamed->pack_start(*hbox_unnamed_password_expiration,
                                     Gtk::PACK_SHRINK);
            hbox_unnamed_password_expiration->pack_start(
                spinbutton_properties_password_expiration, Gtk::PACK_SHRINK);
            Gtk::Label *label_unnamed_password_expiration =
                Gtk::make_managed<Gtk::Label>(
                    "Срок действия пароля, дней\n(0 - нет ограничения)");
            hbox_unnamed_password_expiration->pack_start(
                *label_unnamed_password_expiration, Gtk::PACK_SHRINK);
            button_properties_change_password.set_halign(Gtk::ALIGN_END);
            hbox_unnamed_password_expiration->pack_start(
                button_properties_change_password, Gtk::PACK_EXPAND_WIDGET);
            stack_menu.add(*vbox_properties_menu);
            stack_menu.set_visible_child(*vbox_properties_menu);
            menus[0] = vbox_properties_menu;
            set_margin(*frame_group, 0, 1);
            set_margin(*frame_unnamed, 0, 1);

            Gtk::Box *vbox_user_is_admin =
                Gtk::make_managed<Gtk::Box>(Gtk::ORIENTATION_VERTICAL, 10);
            set_margin(*vbox_user_is_admin, 10, 10);
            Gtk::Label *label_user_is_admin = Gtk::make_managed<Gtk::Label>();

            label_user_is_admin->set_markup(
                "<span size=\"large\"><b>Пользователь имеет\nправа "
                "администратора</b></span>");
            set_margin(*label_user_is_admin, 10, 10);
            label_user_is_admin->set_halign(Gtk::ALIGN_START);
            vbox_user_is_admin->pack_start(*label_user_is_admin,
                                           Gtk::PACK_SHRINK);
            menus[5] = vbox_user_is_admin;
            stack_menu.add(*vbox_user_is_admin);
            stack_menu.show_all();
        }

        void setup_signals() {
            signal_delete_event().connect([this](GdkEventAny *event) {
                (void)event;
                bool ret = on_exit_clicked();
                return ret;
            });
            treeview.get_selection()->signal_changed().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::on_obj_selection_changed));
            paned_main.property_position().signal_changed().connect([&]() {
                int pos = paned_main.get_position();
                int total_width = paned_main.get_allocation().get_width();

                if (pos < TREE_MIN_WIDTH)
                    paned_main.set_position(TREE_MIN_WIDTH);
                else if (pos > total_width - FORM_MIN_WIDTH)
                    paned_main.set_position(total_width - FORM_MIN_WIDTH);
            });

            button_new_group.signal_clicked().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::on_new_group_clicked));
            button_new_user.signal_clicked().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::on_new_user_clicked));
            button_save.signal_clicked().connect(
                sigc::mem_fun(*this, &UserRightsConfigurator::on_save_clicked));
            button_delete.signal_clicked().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::on_delete_clicked));

            entry_properties_name.signal_changed().connect([&]() {
                if (stored_curr_obj_row[obj_cols.name] ==
                    entry_properties_name.get_text())
                    button_properties_apply_name.set_sensitive(false);
                else
                    button_properties_apply_name.set_sensitive(true);
            });
            button_properties_apply_name.signal_clicked().connect(sigc::mem_fun(
                *this, &UserRightsConfigurator::on_apply_name_clicked));
            entry_properties_extrainfo.signal_changed().connect([&]() {
                if (stored_curr_obj_row[obj_cols.extrainfo] ==
                    entry_properties_extrainfo.get_text())
                    return;
                stored_curr_obj_row[obj_cols.extrainfo] =
                    entry_properties_extrainfo.get_text();
                button_save_enable();
            });
            checkbutton_assign_admin_rights.signal_toggled().connect([this]() {
                unsigned char flags = stored_curr_obj_row[obj_cols.flags];
                if (((flags & HAVE_ADMIN_RIGHTS) != 0) ==
                    checkbutton_assign_admin_rights.get_active()) {
                    return;
                }
                stored_curr_obj_row[obj_cols.flags] = flags ^ HAVE_ADMIN_RIGHTS;
                Glib::ustring username = stored_curr_obj_row[obj_cols.username];
                if (username.empty()) {
                    for (const Gtk::TreeModel::Row &child_row :
                         stored_curr_obj_row->children()) {
                        child_row[obj_cols.icon] =
                            checkbutton_assign_admin_rights.get_active()
                                ? pixbuf_admin
                                : pixbuf_user;
                    }
                } else {
                    stored_curr_obj_row[obj_cols.icon] =
                        checkbutton_assign_admin_rights.get_active()
                            ? pixbuf_admin
                            : pixbuf_user;
                }
                button_save_enable();
            });
            checkbutton_allow_password_change.signal_toggled().connect(
                [this]() {
                    unsigned char flags = stored_curr_obj_row[obj_cols.flags];
                    if (((flags & ALLOW_PWD_CHANGE) != 0) ==
                        checkbutton_allow_password_change.get_active()) {
                        return;
                    }
                    stored_curr_obj_row[obj_cols.flags] =
                        flags ^ ALLOW_PWD_CHANGE;
                    button_save_enable();
                });
            checkbutton_allow_to_set_as_default_user.signal_toggled().connect(
                [this]() {
                    unsigned char flags = stored_curr_obj_row[obj_cols.flags];
                    if (((flags & ALLOW_TO_SET_AS_DEF_USER) != 0) ==
                        checkbutton_allow_to_set_as_default_user.get_active()) {
                        return;
                    }
                    stored_curr_obj_row[obj_cols.flags] =
                        flags ^ ALLOW_TO_SET_AS_DEF_USER;
                    button_save_enable();
                });
            checkbutton_require_password_change_on_next_login.signal_toggled()
                .connect([this]() {
                    unsigned char flags = stored_curr_obj_row[obj_cols.flags];
                    if (((flags & REQUIRE_PWD_CHANGE_ON_NEXT_LOGIN) != 0) ==
                        checkbutton_require_password_change_on_next_login
                            .get_active()) {
                        return;
                    }
                    stored_curr_obj_row[obj_cols.flags] =
                        flags ^ REQUIRE_PWD_CHANGE_ON_NEXT_LOGIN;
                    button_save_enable();
                });
            checkbutton_set_as_default_user.signal_toggled().connect([&]() {
                unsigned char flags = stored_curr_obj_row[obj_cols.flags];
                if (((flags & SET_AS_DEF_USER) != 0) ==
                    checkbutton_set_as_default_user.get_active()) {
                    return;
                }
                for (const Gtk::TreeModel::Row &top_child_row :
                     treestore_objs->children()) {
                    for (const Gtk::TreeModel::Row &child_row :
                         top_child_row.children()) {
                        unsigned char child_flags = child_row[obj_cols.flags];
                        child_row[obj_cols.flags] =
                            child_flags & ~SET_AS_DEF_USER;
                    }
                    unsigned char top_child_flags =
                        top_child_row[obj_cols.flags];
                    top_child_row[obj_cols.flags] =
                        top_child_flags & ~SET_AS_DEF_USER;
                }
                stored_curr_obj_row[obj_cols.flags] = flags ^ SET_AS_DEF_USER;
                button_save_enable();
            });
            spinbutton_properties_password_expiration.signal_value_changed()
                .connect([&]() {
                    Glib::ustring username =
                        stored_curr_obj_row[obj_cols.username];
                    int pwdkeepperiod =
                        spinbutton_properties_password_expiration.get_value();
                    if (username.empty()) {
                        stored_curr_obj_row[obj_cols.pwdkeepperiod] =
                            pwdkeepperiod;
                        for (const Gtk::TreeModel::Row &child_row :
                             stored_curr_obj_row->children()) {
                            if (child_row[obj_cols.pwdkeepperiod] ==
                                pwdkeepperiod)
                                return;
                            child_row[obj_cols.pwdkeepperiod] = pwdkeepperiod;
                            button_save_enable();
                        }
                    } else {
                        if (stored_curr_obj_row[obj_cols.pwdkeepperiod] ==
                            pwdkeepperiod)
                            return;
                        stored_curr_obj_row[obj_cols.pwdkeepperiod] =
                            pwdkeepperiod;
                        button_save_enable();
                    }
                });
            button_properties_change_password.signal_clicked().connect(
                [this]() {
                    Glib::ustring password_hash =
                        stored_curr_obj_row[obj_cols.userpassw];
                    if (password_hash.empty()) {
                        ask_new_password("Назначение пароля",
                                         stored_curr_obj_row);
                        return;
                    }

                    Gtk::MessageDialog *dialog = new Gtk::MessageDialog(
                        "Изменение пароля", false, Gtk::MESSAGE_QUESTION,
                        Gtk::BUTTONS_NONE);
                    dialog->add_button("Отмена", Gtk::RESPONSE_CANCEL);
                    dialog->add_button("Ok", Gtk::RESPONSE_OK);
                    Gtk::Box *content_area = dialog->get_content_area();
                    set_margin(*content_area, 5, 5);
                    Gtk::Grid *grid = Gtk::make_managed<Gtk::Grid>();
                    grid->set_column_spacing(25);
                    grid->set_row_spacing(5);
                    content_area->pack_start(*grid, Gtk::PACK_SHRINK);
                    Gtk::Label *label_password_new =
                        Gtk::make_managed<Gtk::Label>("Новый пароль:");
                    label_password_new->set_halign(Gtk::ALIGN_START);
                    Gtk::Entry *entry_password_new =
                        Gtk::make_managed<Gtk::Entry>();
                    entry_password_new->set_visibility(false);
                    entry_password_new->set_input_purpose(
                        Gtk::INPUT_PURPOSE_PASSWORD);
                    grid->attach(*label_password_new, 0, 1, 1, 1);
                    grid->attach(*entry_password_new, 1, 1, 1, 1);
                    Gtk::Label *label_password_new_confirm =
                        Gtk::make_managed<Gtk::Label>(
                            "Подтвердите новый пароль:");
                    label_password_new_confirm->set_halign(Gtk::ALIGN_START);
                    Gtk::Entry *entry_password_new_confirm =
                        Gtk::make_managed<Gtk::Entry>();
                    entry_password_new_confirm->set_visibility(false);
                    entry_password_new_confirm->set_input_purpose(
                        Gtk::INPUT_PURPOSE_PASSWORD);
                    grid->attach(*label_password_new_confirm, 0, 2, 1, 1);
                    grid->attach(*entry_password_new_confirm, 1, 2, 1, 1);
                    Gtk::Separator *separator =
                        Gtk::make_managed<Gtk::Separator>();
                    content_area->pack_start(*separator, Gtk::PACK_SHRINK);
                    set_margin(*separator, 0, 5);
                    dialog->show_all();

                    auto ok_button = dialog->get_widget_for_response(
                        Gtk::ResponseType::RESPONSE_OK);
                    entry_password_new->signal_changed().connect([&]() {
                        ok_button->set_sensitive(
                            entry_password_new->get_text() ==
                            entry_password_new_confirm->get_text());
                    });
                    entry_password_new_confirm->signal_changed().connect([&]() {
                        ok_button->set_sensitive(
                            entry_password_new->get_text() ==
                            entry_password_new_confirm->get_text());
                    });

                    int res = dialog->run();
                    Glib::ustring password_new = entry_password_new->get_text();
                    dialog->close();
                    delete dialog;
                    if (res != Gtk::RESPONSE_OK)
                        return;
                    std::string username = static_cast<Glib::ustring>(
                        stored_curr_obj_row[obj_cols.username]);
                    stored_curr_obj_row[obj_cols.userpassw] =
                        md5_hash(password_new, username);
                    std::string new_pwd_change_dt_str =
                        datetime_to_str(Glib::DateTime::create_now_local());
                    stored_curr_obj_row[obj_cols.lastpwdchangetime] =
                        new_pwd_change_dt_str;
                    button_save_enable();
                    Gtk::MessageDialog dialog_success(
                        "Пароль пользователя изменен", false,
                        Gtk::MESSAGE_INFO);
                    dialog_success.run();
                });
            button_settings.signal_clicked().connect(
                [this]() { on_settings_clicked(); });

            menuitem_save.signal_activate().connect(
                [this]() { on_save_clicked(); });
            menuitem_exit.signal_activate().connect(
                [this]() { on_exit_clicked(); });
            menuitem_new_user.signal_activate().connect(
                [this]() { on_new_user_clicked(); });
            menuitem_new_group.signal_activate().connect(
                [this]() { on_new_group_clicked(); });
            menuitem_delete.signal_activate().connect(
                [this]() { on_delete_clicked(); });
            menuitem_settings.signal_activate().connect(
                [this]() { on_settings_clicked(); });
        }

        void setup_accel_groups() {
            auto accel_group = Gtk::AccelGroup::create();
            add_accel_group(accel_group);
            button_save.add_accelerator("clicked", accel_group, GDK_KEY_s,
                                        Gdk::CONTROL_MASK, Gtk::ACCEL_VISIBLE);
        }

        // Загрузка userlist.ini, ldap0.ini, а также users.xml или его
        // дефолтной конфигурации и ее сохранение
        void setup_data(std::string project_path) {
            std::string errors;
            std::filesystem::path p(project_path);
            if (!std::filesystem::exists(p) || p.filename() != "kaskad.kpr") {
                Gtk::MessageDialog dialog(
                    std::string("Не удалось найти файл проекта по пути: ") +
                        project_path,
                    false, Gtk::MESSAGE_ERROR);
                dialog.run();
                std::exit(1);
            }
            std::string userlist_config_path =
                std::filesystem::path(project_path).parent_path().string() +
                "/Configurator/UserList.ini";
            Glib::ustring users_config_path_parsed = parse_userlist_config(
                userlist_config_path, main_settings, errors);
            if (!errors.empty()) {
                Gtk::MessageDialog dialog(
                    std::string("Не удалось открыть файл конфигурации ") +
                        userlist_config_path + "\n\n" + errors,
                    false, Gtk::MESSAGE_ERROR);
                dialog.run();
                std::exit(1);
            }
            (void)parse_ldap_config(ldap_config_path, main_settings, errors);
            if (!errors.empty()) {
                Gtk::MessageDialog dialog(std::string("Не удалось открыть файл "
                                                      "конфигурации ") +
                                              ldap_config_path + "\n\n" +
                                              errors,
                                          false, Gtk::MESSAGE_ERROR);
                dialog.run();
                errors.clear();
            }

            treestore_objs = Gtk::TreeStore::create(obj_cols);
            treeview.set_model(treestore_objs);
            liststore_actions_apps = Gtk::ListStore::create(action_cols);
            liststore_actions_private = Gtk::ListStore::create(action_cols);
            treestore_zones = Gtk::TreeStore::create(zone_cols);
            auto add_zone_row = [this](const std::string &title, int station_id,
                                       int group_id) {
                Gtk::TreeModel::Row row = *treestore_zones->append();
                row[zone_cols.zonename] = title;
                row[zone_cols.station_id] = station_id;
                row[zone_cols.group_id] = group_id;
            };
            add_zone_row(std::get<0>(DEFAULT_ZONES[0]),
                         std::get<1>(DEFAULT_ZONES[0]),
                         std::get<2>(DEFAULT_ZONES[0]));
            add_zone_row(std::get<0>(DEFAULT_ZONES[1]),
                         std::get<1>(DEFAULT_ZONES[1]),
                         std::get<2>(DEFAULT_ZONES[1]));

            // Создание и сохранение дефолтной конфигурации
            if (!users_config_path_parsed.empty()) {
                users_config_path = users_config_path_parsed;
            } else {
                Gtk::MessageDialog *dialog = new Gtk::MessageDialog(
                    "Расположение файла БД пользователей не указано. "
                    "Желаете "
                    "создать конфигурацию по умолчанию?",
                    false, Gtk::MESSAGE_QUESTION, Gtk::BUTTONS_NONE);
                dialog->add_button("OK", Gtk::RESPONSE_OK);
                dialog->add_button("Отмена", Gtk::RESPONSE_CANCEL);
                int res = dialog->run();
                dialog->close();
                delete dialog;
                if (res != Gtk::RESPONSE_OK)
                    std::exit(0);
                Gtk::FileChooserDialog fs_dialog =
                    Gtk::FileChooserDialog("", Gtk::FILE_CHOOSER_ACTION_SAVE);
                fs_dialog.add_button("OK", Gtk::RESPONSE_ACCEPT);
                fs_dialog.add_button("Отмена", Gtk::RESPONSE_CANCEL);
                fs_dialog.set_current_folder(
                    std::filesystem::path(project_path).parent_path());
                int fs_res = fs_dialog.run();
                if (fs_res != Gtk::RESPONSE_ACCEPT)
                    std::exit(0);
                Glib::ustring users_config_path_new = fs_dialog.get_filename();
                users_config_path = users_config_path_new;

                // Дефолтные приложения
                for (const auto &default_app : DEFAULT_APPS) {
                    Gtk::TreeModel::Row new_row =
                        *liststore_actions_apps->append();
                    new_row[action_cols.appname] = std::get<0>(default_app);
                    new_row[action_cols.description] = std::get<1>(default_app);
                    Glib::RefPtr<Gdk::Pixbuf> pixbuf;
                    (void)set_hexcoded_icon(pixbuf, std::get<2>(default_app));
                    new_row[action_cols.icon] = pixbuf;
                    new_row[action_cols.globactmask] = std::get<3>(default_app);
                }
                // Дефолтные приватные действия
                for (const auto &default_private_action : DEFAULT_ACTIONS) {
                    Gtk::TreeModel::Row new_row =
                        *liststore_actions_private->append();
                    new_row[action_cols.appname] =
                        std::get<0>(default_private_action);
                    new_row[action_cols.actionname] =
                        std::get<1>(default_private_action);
                    new_row[action_cols.action_id] =
                        std::get<2>(default_private_action);
                    new_row[action_cols.description] =
                        std::get<3>(default_private_action);
                    Glib::RefPtr<Gdk::Pixbuf> pixbuf;
                    (void)set_hexcoded_icon(
                        pixbuf, std::get<4>(default_private_action));
                    new_row[action_cols.icon] = pixbuf;
                }
                Gtk::TreeModel::Row public_row = *treestore_objs->append();
                public_row[obj_cols.icon] = pixbuf_user;
                public_row[obj_cols.username] = "PUBLIC";
                public_row[obj_cols.name] = "Public";
                public_row[obj_cols.pwdkeepperiod] = 6;
                Glib::DateTime now = Glib::DateTime::create_now_local();
                public_row[obj_cols.registertime] = datetime_to_str(now);
                public_row[obj_cols.lastpwdchangetime] = datetime_to_str(now);
                public_row[obj_cols.lastentertime] = datetime_to_str(now);
                public_row[obj_cols.pwdkeepperiod] = 0;
                public_row[obj_cols.userpassw] = md5_hash("", "PUBLIC");
                Gtk::TreeModel::Row admin_row = *treestore_objs->append();
                admin_row[obj_cols.icon] = pixbuf_admin;
                admin_row[obj_cols.username] = "ADMIN";
                admin_row[obj_cols.name] = "admin";
                admin_row[obj_cols.pwdkeepperiod] = 6;
                admin_row[obj_cols.registertime] = datetime_to_str(now);
                admin_row[obj_cols.lastpwdchangetime] = datetime_to_str(now);
                admin_row[obj_cols.lastentertime] = datetime_to_str(now);
                admin_row[obj_cols.flags] = HAVE_ADMIN_RIGHTS;
                admin_row[obj_cols.pwdkeepperiod] = 0;
                admin_row[obj_cols.userpassw] = md5_hash("masterkey", "ADMIN");
                // Сохранение конфигурации
                on_save_clicked();

                // Обновление userlist.ini
                main_settings.new_users_config_path = users_config_path;
                std::string errors;
                int ret_backup_userlist =
                    write_userlist_backup(userlist_config_path, errors);
                if (ret_backup_userlist == 0)
                    (void)write_userlist_config(userlist_config_path,
                                                main_settings, errors);
                if (!errors.empty()) {
                    Gtk::MessageDialog dialog(
                        std::string("Не удалось сохранить конфигурацию по "
                                    "умолчанию\n\n") +
                            errors,
                        false, Gtk::MESSAGE_ERROR);
                    dialog.run();
                }
                treeview.get_selection()->select(
                    treestore_objs->children().begin());
                return;
            }

            parse_users_config(users_config_path, treestore_objs, obj_cols,
                               liststore_actions_apps,
                               liststore_actions_private, action_cols,
                               treestore_zones, zone_cols, errors);
            if (!errors.empty()) {
                Gtk::MessageDialog dialog(
                    std::string(
                        "Не удалось открыть файл базы данных пользователей ") +
                        users_config_path + "\n\n" + errors,
                    false, Gtk::MESSAGE_ERROR);
                dialog.run();
                std::exit(1);
            }

            // Смена пароля если срок действия пароля истек или назначена
            // смена пароля при следуюшем входе в систему
            auto check_for_required_password_change =
                [&](Gtk::TreeModel::Row row) {
                    bool expiration_change = false;
                    bool required_change = false;
                    Glib::ustring last_pwd_change_dt_str =
                        row[obj_cols.lastpwdchangetime];
                    Glib::DateTime last_pwd_change_dt =
                        parse_datetime(last_pwd_change_dt_str);
                    int pwd_keep_period =
                        static_cast<int>(row[obj_cols.pwdkeepperiod]);
                    Glib::DateTime now = Glib::DateTime::create_now_local();
                    if (pwd_keep_period != 0) {
                        Glib::DateTime pwd_expiration_dt =
                            last_pwd_change_dt.add_days(pwd_keep_period);
                        if (now.compare(pwd_expiration_dt) > 0) {
                            expiration_change = true;
                        }
                    }
                    unsigned char flags = row[obj_cols.flags];
                    if ((row[obj_cols.flags] &
                         REQUIRE_PWD_CHANGE_ON_NEXT_LOGIN) != 0) {
                        required_change = true;
                    }
                    if (required_change || expiration_change) {
                        bool password_changed = ask_new_password(
                            expiration_change ? "Замена истекшего пароля"
                                              : "Требуется смена пароля",
                            row);
                        if (password_changed) {
                            if (required_change) {
                                row[obj_cols.flags] =
                                    flags ^ REQUIRE_PWD_CHANGE_ON_NEXT_LOGIN;
                            }
                            if (expiration_change) {
                                row[obj_cols.lastpwdchangetime] =
                                    datetime_to_str(now);
                            }
                        }

                        (void)write_users_config(
                            users_config_path, main_settings, treestore_objs,
                            obj_cols, liststore_actions_apps,
                            liststore_actions_private, action_cols,
                            treestore_zones, zone_cols, errors);
                    }
                };

            // Проверка на принудительную смену паролей пользователей,
            // установка иконок
            for (const Gtk::TreeModel::Row &top_child_row :
                 treestore_objs->children()) {
                unsigned char top_child_flags = top_child_row[obj_cols.flags];
                Glib::ustring username = top_child_row[obj_cols.username];
                if (username.empty()) {
                    for (const Gtk::TreeModel::Row &child_row :
                         top_child_row.children()) {
                        unsigned char child_flags = child_row[obj_cols.flags];
                        child_row[obj_cols.icon] =
                            ((top_child_flags & HAVE_ADMIN_RIGHTS) != 0 ||
                             (child_flags & HAVE_ADMIN_RIGHTS) != 0)
                                ? pixbuf_admin
                                : pixbuf_user;
                        check_for_required_password_change(child_row);
                    }
                    combobox_properties_group.append(
                        top_child_row[obj_cols.name]);
                    top_child_row[obj_cols.icon] = pixbuf_group;
                } else {
                    top_child_row[obj_cols.icon] =
                        (top_child_flags & HAVE_ADMIN_RIGHTS) != 0
                            ? pixbuf_admin
                            : pixbuf_user;
                    check_for_required_password_change(top_child_row);
                }
            }
            treeview.get_selection()->select(
                treestore_objs->children().begin());
            treeview.expand_all();
        }

        Gtk::HeaderBar header_bar;
        Gtk::Box vbox_top{Gtk::ORIENTATION_VERTICAL, 10};
        Gtk::Box vbox_main{Gtk::ORIENTATION_VERTICAL, 10};
        Gtk::Box top_bar{Gtk::ORIENTATION_HORIZONTAL, 10};
        Gtk::Separator top_bar_separator1{Gtk::ORIENTATION_VERTICAL};
        Gtk::Separator top_bar_separator2{Gtk::ORIENTATION_VERTICAL};
        Gtk::Separator top_bar_separator3{Gtk::ORIENTATION_VERTICAL};
        Gtk::Paned paned_main{Gtk::ORIENTATION_HORIZONTAL};
        Gtk::Frame frame_tree_objs;
        Gtk::Box vbox_form{Gtk::ORIENTATION_VERTICAL, 0};
        Gtk::Box hbox_form_buttons_bar{Gtk::ORIENTATION_HORIZONTAL, 10};
        Gtk::Frame frame_stack_menu;

        Gtk::MenuButton menubutton_file, menubutton_users, menubutton_service,
            menubutton_help;
        Gtk::Menu menu_file, menu_users, menu_service, menu_help;
        Gtk::MenuItem menuitem_save, menuitem_exit, menuitem_new_user,
            menuitem_new_group, menuitem_delete, menuitem_settings,
            menuitem_help;
        Gtk::Image menuitem_save_icon, menuitem_exit_icon,
            menuitem_new_user_icon, menuitem_new_group_icon,
            menuitem_delete_icon, menuitem_settings_icon, menuitem_help_icon;
        Gtk::Label menuitem_save_label, menuitem_exit_label,
            menuitem_new_user_label, menuitem_new_group_label,
            menuitem_delete_label, menuitem_settings_label, menuitem_help_label;
        Gtk::Box menuitem_save_box{Gtk::ORIENTATION_HORIZONTAL, 5},
            menuitem_exit_box{Gtk::ORIENTATION_HORIZONTAL, 5},
            menuitem_new_user_box{Gtk::ORIENTATION_HORIZONTAL, 5},
            menuitem_new_group_box{Gtk::ORIENTATION_HORIZONTAL, 5},
            menuitem_delete_box{Gtk::ORIENTATION_HORIZONTAL, 5},
            menuitem_settings_box{Gtk::ORIENTATION_HORIZONTAL, 5},
            menuitem_help_box{Gtk::ORIENTATION_HORIZONTAL, 5};

        Gtk::Stack stack_menu;
        std::vector<Gtk::RadioButton *> radiobuttons_form_buttons_bar;
        std::vector<Gtk::Box *> menus;
        Gtk::Label label_info;
        Gtk::Button button_new_group, button_new_user, button_save,
            button_delete, button_settings, button_apply;
        Gtk::Image button_save_icon, button_delete_icon, button_new_user_icon,
            button_new_group_icon, button_settings_icon;
        Glib::RefPtr<Gdk::Pixbuf> pixbuf_save_enabled, pixbuf_save_disabled,
            pixbuf_delete, pixbuf_user, pixbuf_admin, pixbuf_group,
            pixbuf_new_user, pixbuf_new_group, pixbuf_settings, pixbuf_help;
        Gtk::CellRendererPixbuf renderer_icon;
        Gtk::CellRendererText renderer_name;
        Gtk::TreeViewColumn treecolumn_icon_name;
        Gtk::RadioButton::Group radiogroup_menu;
        Gtk::ScrolledWindow scrolled_tree_objs, scrolled_form_objs;
        Gtk::TreeView treeview;

        // Меню свойств
        Gtk::Label label_properties_is_group;
        Gtk::Button button_properties_apply_name = Gtk::Button("Применить");
        Gtk::Entry entry_properties_name, entry_properties_extrainfo;
        Gtk::Label label_properties_group;
        Gtk::ComboBoxText combobox_properties_group;
        Gtk::CheckButton checkbutton_assign_admin_rights =
            Gtk::CheckButton("Назначить права администратора");
        Gtk::CheckButton checkbutton_allow_password_change =
            Gtk::CheckButton("Разрешить смену пароля пользователем");
        Gtk::CheckButton checkbutton_allow_to_set_as_default_user =
            Gtk::CheckButton(
                "Разрешить назначать себя пользователем по умолчанию");
        Gtk::CheckButton checkbutton_require_password_change_on_next_login =
            Gtk::CheckButton("Потребовать смену пароля при следующем входе");
        Gtk::CheckButton checkbutton_set_as_default_user =
            Gtk::CheckButton("Назначить пользователем по умолчанию");
        Gtk::SpinButton spinbutton_properties_password_expiration =
            Gtk::SpinButton(Gtk::Adjustment::create(0, 0, 356, 1));
        Gtk::Label label_properties_default_arm;
        Gtk::ComboBoxText combobox_properties_arms;
        Gtk::Button button_properties_change_password =
            Gtk::Button("Сменить пароль");
        // Меню статистики
        Gtk::Entry *entry_statistics_registration_date,
            *entry_statistics_last_login_date,
            *entry_statistics_last_password_change_date,
            *entry_statistics_password_expiration_date;

        Gtk::TreeView treeview_actions_apps;
        Gtk::TreeView treeview_actions_public;
        Gtk::TreeView treeview_actions_private;
        Glib::RefPtr<Gtk::ListStore> liststore_actions_apps;
        Gtk::TreeViewColumn treecolumn_toggle_apps_group;
        Gtk::TreeModel::Row stored_prev_app_row;
        Glib::RefPtr<Gtk::ListStore> liststore_actions_public;
        Gtk::TreeViewColumn treecolumn_toggle_public_group;
        Glib::RefPtr<Gtk::ListStore> liststore_actions_private;
        Gtk::TreeViewColumn treecolumn_toggle_private_group;
        Glib::RefPtr<Gtk::TreeModelFilter> public_filter_model;
        Glib::RefPtr<Gtk::TreeModelFilter> private_filter_model;
        ActionCols action_cols;
        Gtk::TreeView treeview_arms;
        Glib::RefPtr<Gtk::ListStore> liststore_arms;
        ArmCols arm_cols;
        Gtk::TreeView treeview_zones;
        Glib::RefPtr<Gtk::TreeStore> treestore_zones;
        ZoneCols zone_cols;

        MainSettings main_settings;
        Glib::RefPtr<Gtk::TreeStore> treestore_objs;
        // Используется при обновлении элементов формы для эффективного
        // последовательного доступа к данным выбранного обьекта
        Gtk::TreeModel::Row stored_curr_obj_row;
        ObjCols obj_cols;
        unsigned char curr_menu_idx = 0;
        std::string userlist_config_path;
        std::string ldap_config_path;
        std::string users_config_path;
        bool unsaved = false;
};

int main(int argc, char *argv[]) {
    std::string project_path;
    if (argc > 1) {
        project_path = argv[1];
    } else {
        project_path = "/usr/share/SCADAProject/kaskad.kpr";
    }

    auto app = Gtk::Application::create("kaskad.users-configurator");
    UserRightsConfigurator window(project_path);
    return app->run(window);
}
