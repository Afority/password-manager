#include "MainWindow.h"

MainWindow::MainWindow(QWidget *parent) : QWidget(parent)
{
    setupUi();
}

void MainWindow::setupUi()
{
    mainLayout = new QVBoxLayout();

    QLabel *passwordLabel = new QLabel("Введите мастер-пароль");
    masterPasswordInput = new QLineEdit;
    masterPasswordInput->setPlaceholderText("Пароль...");
    QPushButton *confirmPasswordButton = new QPushButton("Подтвердить");

    connect(masterPasswordInput, &QLineEdit::textChanged, this, &MainWindow::updateMasterPassword);
    connect(confirmPasswordButton, &QPushButton::clicked, this, &MainWindow::handleMasterPassword);
    
    mainLayout->addWidget(passwordLabel);
    mainLayout->addWidget(masterPasswordInput);
    mainLayout->addWidget(confirmPasswordButton);

    setLayout(mainLayout);
}

void MainWindow::drawMain()
{
    Crypto crypto;
    std::ifstream fileIn("/home/almas/Desktop/password_manager/data.json");
    nlohmann::json data = nlohmann::json::parse(fileIn);
    fileIn.close();

    if (data.empty())
    {
        // Handle empty data if needed
    }
    else
    {
        int index = 0;
        for (const auto& entry : data)
        {
            addPasswordEntry(entry, index++, crypto);
        }
    }

    setupPasswordEntryForm();
}

void MainWindow::addPasswordEntry(const nlohmann::json& entry, int index, Crypto& crypto)
{
    QVBoxLayout *entryLayout = new QVBoxLayout();
    
    std::string login, password, site;
    decryptEntry(entry, crypto, login, password, site);
    
    if (login.empty())
    {
        QMessageBox::information(this, "Error", "Неверный мастер-пароль!");
        QApplication::exit(1);
    }

    if (!site.empty())
    {
        createEntryField(entryLayout, "Сайт:", site);
    }
    
    createEntryField(entryLayout, "Логин:", login);
    createEntryField(entryLayout, "Пароль:", password);

    QWidget* spacer = new QWidget();
    spacer->setMinimumSize(1, 10);
    spacer->setMaximumSize(1, 10);
    entryLayout->addWidget(spacer);

    mainLayout->insertLayout(passwordEntries.size(), entryLayout);
    passwordEntries.push_back(entryLayout);
}

void MainWindow::decryptEntry(const nlohmann::json& entry, Crypto& crypto, std::string& login, std::string& password, std::string& site)
{
    std::string encryptedLogin = hexToString(entry["login"]);
    std::string encryptedPassword = hexToString(entry["password"]);
    std::string encryptedSite = hexToString(entry["site"]);
    
    login = crypto.decrypt(encryptedLogin, masterPassword);
    password = crypto.decrypt(encryptedPassword, masterPassword);
    site = crypto.decrypt(encryptedSite, masterPassword);
}

void MainWindow::createEntryField(QVBoxLayout *layout, const std::string& labelText, const std::string& fieldValue)
{
    QHBoxLayout *fieldLayout = new QHBoxLayout();
    
    QLabel *label = new QLabel(labelText.c_str());
    label->setMinimumSize(70, 1);
    
    QLineEdit *field = new QLineEdit(fieldValue.c_str());
    field->setReadOnly(true);
    
    QPushButton *copyButton = new QPushButton("Копировать");
    connect(copyButton, &QPushButton::clicked, this, [field]() {
        QClipboard *clipboard = QApplication::clipboard();
        clipboard->setText(field->text());
    });
    
    fieldLayout->addWidget(label);
    fieldLayout->addWidget(field);
    fieldLayout->addWidget(copyButton);
    
    layout->addLayout(fieldLayout);
}

void MainWindow::setupPasswordEntryForm()
{
    QVBoxLayout *formLayout = new QVBoxLayout();

    QLabel *formLabel = new QLabel("Добавить пароль");

    siteInput = new QLineEdit;
    siteInput->setPlaceholderText("Сайт");
    siteInput->setFixedSize(230, 35);

    loginInput = new QLineEdit;
    loginInput->setPlaceholderText("Логин");
    loginInput->setFixedSize(230, 35);

    passwordInput = new QLineEdit;
    passwordInput->setPlaceholderText("Пароль");
    passwordInput->setFixedSize(230, 35);

    QPushButton *submitButton = new QPushButton("Добавить");
    connect(submitButton, &QPushButton::clicked, this, &MainWindow::submitPasswordEntry);
    
    connect(siteInput, &QLineEdit::textChanged, this, &MainWindow::updateSite);
    connect(loginInput, &QLineEdit::textChanged, this, &MainWindow::updateLogin);
    connect(passwordInput, &QLineEdit::textChanged, this, &MainWindow::updatePassword);
    
    formLayout->addWidget(formLabel);
    formLayout->addWidget(siteInput);
    formLayout->addWidget(loginInput);
    formLayout->addWidget(passwordInput);
    formLayout->addWidget(submitButton);

    mainLayout->addLayout(formLayout);
}

void MainWindow::submitPasswordEntry()
{
    if (login.empty() || password.empty())
    {
        QMessageBox::information(this, "Info", "Не все поля заполнены");
        return;
    }

    std::ifstream fileIn("/home/almas/Desktop/password_manager/data.json");
    nlohmann::json data = nlohmann::json::parse(fileIn);
    fileIn.close();

    nlohmann::json newEntry;

    Crypto crypto;
    newEntry["login"] = stringToHex(crypto.encrypt(login, masterPassword));
    newEntry["password"] = stringToHex(crypto.encrypt(password, masterPassword));
    newEntry["site"] = stringToHex(crypto.encrypt(site, masterPassword));

    data.push_back(newEntry);

    std::ofstream fileOut("/home/almas/Desktop/password_manager/data.json");
    fileOut << data.dump();
    fileOut.close();
    
    addPasswordEntry(newEntry, passwordEntries.size(), crypto);
    
    siteInput->clear();
    loginInput->clear();
    passwordInput->clear();
}

void MainWindow::handleMasterPassword()
{
    deleteMasterPasswordPrompt();
    drawMain();
}

void MainWindow::deleteMasterPasswordPrompt()
{
    mainLayout->takeAt(0)->widget()->deleteLater();
    mainLayout->takeAt(0)->widget()->deleteLater();
    mainLayout->takeAt(0)->widget()->deleteLater();
}

void MainWindow::updateMasterPassword(const QString &password)
{
    masterPassword = password.toStdString();
}

void MainWindow::updatePassword(const QString &password)
{
    this->password = password.toStdString();
}

void MainWindow::updateLogin(const QString &login)
{
    this->login = login.toStdString();
}

void MainWindow::updateSite(const QString &site)
{
    this->site = site.toStdString();
}
