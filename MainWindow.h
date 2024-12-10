#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QPointer>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include "json.hpp"
#include "utils.hpp"

#include <fstream>
#include <vector>
#include <string>

class MainWindow : public QWidget {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private:
    QVBoxLayout* mainLayout;

    std::string masterPassword;
    std::string password;
    std::string login;
    std::string site;

    QPointer<QLineEdit> masterPasswordInput;
    QPointer<QLineEdit> siteInput;
    QPointer<QLineEdit> loginInput;
    QPointer<QLineEdit> passwordInput;

    std::vector<QPointer<QVBoxLayout>> passwordEntries;

    void setupUi();
    void drawMain();
    void addPasswordEntry(const nlohmann::json& entry, int index, Crypto& crypto);
    void decryptEntry(const nlohmann::json& entry, Crypto& crypto, std::string& login, std::string& password, std::string& site);
    void createEntryField(QVBoxLayout *layout, const std::string& labelText, const std::string& fieldValue);
    void setupPasswordEntryForm();

private slots:
    void updateMasterPassword(const QString &text);
    void updatePassword(const QString &text);
    void updateLogin(const QString &text);
    void updateSite(const QString &text);
    void submitPasswordEntry();
    void handleMasterPassword();
    void deleteMasterPasswordPrompt();
};
