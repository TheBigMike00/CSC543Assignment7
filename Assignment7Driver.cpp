#include "SHA256.h"
using namespace std;

int main()
{
    //read file https://www.w3schools.com/cpp/cpp_files.asp
    string entireText = "";
    string tempText;
    ifstream MyReadFile("BookOfMark.txt");

    while (getline(MyReadFile, tempText))
        entireText = entireText + tempText;
    MyReadFile.close();

    string messageToHash = entireText;
    //string messageToHash = "a";

    SHA256* theHash = new SHA256(messageToHash);

    cout << theHash->displayOG_Message() << "\n\n";
    cout << theHash->displayHash() << "\n\n";
}