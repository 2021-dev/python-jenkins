#include <iostream>
#include <postgres/include/postgresql/libpq-fe.h>
#include <openssl/ssl.h>
#include <libpg/include/pg_lib.h>
#include <string>
#include <cstdlib>
#include <cstring>

// 空指针漏洞
void nullPointerExample() {
    int *ptr = nullptr;
    std::cout << "Dereferencing a null pointer: " << *ptr << std::endl; // 空指针漏洞
}

// 缓冲区溢出漏洞
void bufferOverflowExample() {
    char buffer[5];
    std::string input;
    std::cout << "Enter a string: ";
    std::cin >> input;

    // 使用 strcpy 函数将输入的字符串拷贝到缓冲区中
    strcpy(buffer, input.c_str()); // 缓冲区溢出漏洞

    std::cout << "Buffer content: " << buffer << std::endl;
}

// 内存泄漏的漏洞
void memoryLeakExample() {
    // 分配内存空间
    int* ptr = new int;
    *ptr = 10;

    // 不释放内存
    // delete ptr; // 这一行注释掉，导致内存泄漏

    // 此处使用ptr指针，但实际上内存已经泄漏
    std::cout << "Value: " << *ptr << std::endl;
}

// 使用不安全的函数
void unsafeFunctionExample() {
    char source[] = "Hello, world!"; // 13个字符 + 1个空字符
    char destination[10]; // 目标缓冲区大小只有10个字符

    // 使用不安全的strcpy函数
    strcpy(destination, source); // 缓冲区溢出，destination没有足够的空间容纳source

    // 输出结果可能会不正确
    std::cout << "Destination: " << destination << std::endl;
}

// 命令行注入
void commandInjectionExample() {
    std::string username;
    std::cout << "Enter your username: ";
    std::cin >> username;

    std::string command = "echo Hello, " + username;
    // 注意：这里并没有对用户输入进行过滤或转义，存在命令行注入漏洞

    // 执行命令
    int result = system(command.c_str());

    if (result != 0) {
        std::cout << "Command execution failed!" << std::endl;
    }
}

// 信息泄露漏洞示例
void informationLeakExample() {
    std::string password;
    std::cout << "Enter your password: ";
    std::cin >> password;

    // 在这里执行一些其他的操作，假设有一些敏感信息

    // 由于某种原因，我们误将密码输出到日志文件中
    std::ofstream logfile("log.txt");
    logfile << "Password: " << password << std::endl;
    logfile.close();

    // 继续执行其他操作

    // 在这里，由于错误地将密码输出到日志文件，导致密码泄露
}

// 不当的访问控制漏洞示例
void improperAccessControlExample() {
    bool isAdmin = false;
    std::string username;
    std::cout << "Enter your username: ";
    std::cin >> username;

    if (username == "admin") {
        isAdmin = true;
    }

    // 在这里假设isAdmin为true代表用户是管理员
    if (isAdmin) {
        // 执行一些敏感操作，比如删除数据库等
        std::cout << "Welcome, administrator!" << std::endl;
    } else {
        // 普通用户只能执行一些有限的操作
        std::cout << "Welcome, user!" << std::endl;
    }
}

// 路径遍历漏洞示例
void pathTraversalExample() {
    std::string filename;
    std::cout << "Enter a filename: ";
    std::cin >> filename;

    // 使用危险函数拼接文件路径
    std::string path = "/home/user/files/" + filename;

    // 假设用户可以任意输入filename
    // 由于没有对输入进行过滤或验证，攻击者可以输入../等特殊字符，导致路径遍历漏洞
    std::ifstream file(path);
    if (file.is_open()) {
        // 读取文件内容
        std::string content;
        while (std::getline(file, content)) {
            std::cout << content << std::endl;
        }
        file.close();
    } else {
        std::cout << "File not found." << std::endl;
    }
}

// SQL注入漏洞示例
void sqlInjectionExample() {
    std::string username;
    std::cout << "Enter your username: ";
    std::cin >> username;

    // 假设该函数用于查询数据库中的用户信息
    // 使用了危险函数拼接SQL查询语句
    std::string query = "SELECT * FROM users WHERE username='" + username + "'";

    // 假设该函数通过执行SQL查询获取用户信息
    // 由于没有对输入进行过滤或转义，存在SQL注入漏洞
    // 攻击者可以通过输入恶意的用户名绕过认证，访问其他用户的信息
    executeSQLQuery(query);
}



int main() {
    // 使用 PostgreSQL 库
    PGconn *conn = PQconnectdb("user=myuser password=mypassword dbname=mydb");
    if (PQstatus(conn) == CONNECTION_OK) {
        std::cout << "Connected to PostgreSQL successfully!" << std::endl;
    } else {
        std::cout << "Failed to connect to PostgreSQL." << std::endl;
    }
    PQfinish(conn);

    // 使用 OpenSSL 库
    SSL_library_init();
    std::cout << "OpenSSL initialized successfully!" << std::endl;

    // 使用 libpg 库
    int pgResult = pg_lib_function();
    std::cout << "libpg function returned: " << pgResult << std::endl;

    // 调用各个漏洞示例
    nullPointerExample();
    bufferOverflowExample();
    memoryLeakExample();
    unsafeFunctionExample();
    commandInjectionExample();
    improperAccessControlExample();
    informationLeakExample();
    pathTraversalExample();
    sqlInjectionExample();

    return 0;
}

