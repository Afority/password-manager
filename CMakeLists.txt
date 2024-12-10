cmake_minimum_required(VERSION 3.31.1)
project(PasswordManager)

set(CMAKE_CXX_STANDARD 17)
find_package(Qt5Widgets REQUIRED)

# Источник исходных файлов проекта
set(COUNTER_APP_SOURCES main.cpp MainWindow.cpp)
set(COUNTER_APP_HEADERS MainWindow.h)

# Генерация MOC-файлов
qt5_wrap_cpp(MOC_FILES ${COUNTER_APP_HEADERS})

# Создаем исполняемый файл и связываем его с Qt5 и CURL
add_executable(PasswordManager ${COUNTER_APP_SOURCES} ${MOC_FILES})
target_link_libraries(PasswordManager Qt5::Widgets ssl crypto z sqlite3)
# -lcrypto -lz -lsqlite3