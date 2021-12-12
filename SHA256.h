#pragma once
#include <iostream>
#include <string.h>
#include <bitset>
#include <sstream>
#include <fstream>
#include <vector>
using namespace std;


class SHA256
{

private:
	string message;
	string messageHash;
	string convertStrToBit(string theMessage);
	string pleasePad(string bitMessage);

	//Helpers - alter bits
	string ch(bitset<32> str1, bitset<32> str2, bitset<32> str3);
	string maj(bitset<32> a, bitset<32> b, bitset<32> c);
	string doBinaryMath(string num1, string num2, string num3, string num4, string num5);
	string goRight(string message, int num);
	string rotateRight(string message, int num);

	//Make updates
	string s0(string message);
	string s1(string message);
	string s2(string message);
	string s3(string message);

public:
	SHA256(string theMessage);
	string displayHash();
	string displayOG_Message();

};