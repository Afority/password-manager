#include <QApplication>

#include "MainWindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    MainWindow window;
    window.setWindowTitle("Password manager");
    window.setMinimumSize(406,332);
    window.show();
    
    return app.exec();
}