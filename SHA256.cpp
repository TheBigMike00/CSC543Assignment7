#include "SHA256.h"

SHA256::SHA256(string theMessage)
{
    this->message = theMessage;

    //Based off Wiki Pseudocode...

    //Initialize hash vals
    unsigned int h0 = 0x6a09e667;
    unsigned int h1 = 0xbb67ae85;
    unsigned int h2 = 0x3c6ef372;
    unsigned int h3 = 0xa54ff53a;
    unsigned int h4 = 0x510e527f;
    unsigned int h5 = 0x9b05688c;
    unsigned int h6 = 0x1f83d9ab;
    unsigned int h7 = 0x5be0cd19;

    //Initialize round constants
    vector<unsigned int> k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };


    //Pre-processing (Padding)
    string bitstr = convertStrToBit(message);
    string paddedstr = pleasePad(bitstr);
    int remLength = paddedstr.length();
    int numChunks = 0;

    //Process the message in successive 512 - bit chunks
    // - get # of chunks
    while (remLength != 0)
    {
        vector<vector<string>> chunks;
        //Extend the first 16 words into the remaining 48 words
        string currentString = paddedstr.substr((numChunks * 512), ((numChunks + 1) * 512));
        vector<string> extend;
        int count = 0;

        for (int i = 0; i < 16; i++)
        {
            string temp;
            for (int j = count; j < (count + 32); j++)
                temp = temp + currentString[j];

            extend.push_back(temp);
            count += 32;
        }

        for (int j = 16; j < 64; j++)
        {
            string _s0 = extend[j - 16];
            string update0 = s0(extend[j - 15]);

            string _s1 = extend[j - 7];
            string update1 = s1(extend[j - 2]);

            string total = doBinaryMath(_s0, update0, _s1, update1, "");
            extend.push_back(total);
        }
        chunks.push_back(extend);

        //Initialize working variables to current hash value:
        unsigned int a, b, c, d, e, f, g, h;
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;

        //Compression function main loop:
        for (int j = 0; j < 64; j++)
        {
            string update2 = s2(bitset<32>(e).to_string());
            string seeH = ch(e, f, g);
            string temp1 = doBinaryMath(bitset<32>(h).to_string(), update2, seeH, bitset<32>(k[j]).to_string(), extend[j]);

            string update3 = s3(bitset<32>(a).to_string());
            string _maj = maj(a, b, c);
            string temp2 = doBinaryMath(update3, _maj, "", "", "");


            h = g;
            g = f;
            f = e;
            e = d + int(bitset<32>(temp1).to_ulong());
            d = c;
            c = b;
            b = a;
            a = int(bitset<32>(temp1).to_ulong()) + int(bitset<32>(temp2).to_ulong());
        }

        //Add the compressed chunk to the current hash value
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
        h5 = h5 + f;
        h6 = h6 + g;
        h7 = h7 + h;

        remLength -= 512;
        numChunks++;
    }

    //Produce the final hash value (big-endian):
    std::stringstream h0Hash, h1Hash, h2Hash, h3Hash, h4Hash, h5Hash, h6Hash, h7Hash;
    h0Hash << std::hex << h0;
    h1Hash << std::hex << h1;
    h2Hash << std::hex << h2;
    h3Hash << std::hex << h3;
    h4Hash << std::hex << h4;
    h5Hash << std::hex << h5;
    h6Hash << std::hex << h6;
    h7Hash << std::hex << h7;

    this->messageHash = h0Hash.str() + h1Hash.str() + h2Hash.str() + h3Hash.str() + h4Hash.str() + h5Hash.str() + h6Hash.str() + h7Hash.str();
}

string SHA256::convertStrToBit(string theMessage)
{
    string output;
    for (int i = 0; i < theMessage.size(); i++)
    {
        output += bitset<8>(theMessage.c_str()[i]).to_string();
    }
    return output;
}

string SHA256::pleasePad(string bitMessage)
{
    string output = bitMessage;
    int length = bitMessage.size();

    bool shouldContinue = true;
    int count = 0;
    string pad = "1";

    while (shouldContinue)
    {
        if ((count + 64 + length + 1) % 512 == 0)
        {
            for (int i = 0; i < count; i++)
                pad += "0";

            shouldContinue = false;
            output += pad;
        }
        else
            count++;
    }
    string lenBinary = bitset<64>(length).to_string();
    output += lenBinary;

    return output;
}

string SHA256::ch(bitset<32> E, bitset<32> F, bitset<32> G)
{
    //pseudo -> (e and f) xor ((not e) and g)
    return ((E & F) ^ (~E & G)).to_string();
}

string SHA256::maj(bitset<32> a, bitset<32> b, bitset<32> c)
{
    //pseudo -> (a and b) xor (a and c) xor (b and c)
    return ((a & b) ^ (a & c) ^ (b & c)).to_string();
}

string SHA256::doBinaryMath(string num1, string num2, string num3, string num4, string num5)
{
    unsigned long n1, n2, n3, n4, n5, total;

    if (num3 == "")
    {
        n1 = bitset<32>(num1).to_ulong();
        n2 = bitset<32>(num2).to_ulong();
        total = n1 + n2;

        return bitset<32>(total).to_string();
    }
    else if (num5 == "")
    {
        n1 = bitset<32>(num1).to_ulong();
        n2 = bitset<32>(num2).to_ulong();
        n3 = bitset<32>(num3).to_ulong();
        n4 = bitset<32>(num4).to_ulong();
        total = n1 + n2 + n3 + n4;

        return bitset<32>(total).to_string();
    }
    else
    {
        n1 = bitset<32>(num1).to_ulong();
        n2 = bitset<32>(num2).to_ulong();
        n3 = bitset<32>(num3).to_ulong();
        n4 = bitset<32>(num4).to_ulong();
        n5 = bitset<32>(num4).to_ulong();
        total = n1 + n2 + n3 + n4 + n5;

        return bitset<32>(total).to_string();
    }
}

string SHA256::goRight(string value, int num)
{
    string temp;
    for (int i = 0; i < num; i++)
        temp = temp + '0';

    for (int j = 0; j < (value.size() - num); j++)
        temp = temp + value[j];

    return temp;
}

string SHA256::rotateRight(string message, int num)
{
    //rotate a string
    //"orange", 3 -> "ngeora"
    string s1 = message.substr(0, num); //ora
    string s2 = message.substr(num, message.length()); //nge

    return s2 + s1;
}

string SHA256::s0(string message)
{
    //s0 of wiki pseudo -> s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
    string rr7 = rotateRight(message, 7);
    string rr18 = rotateRight(message, 18);
    string right3 = goRight(message, 3);

    return (std::bitset<32>(rr7) ^ std::bitset<32>(rr18) ^ std::bitset<32>(right3)).to_string();
}

string SHA256::s1(string message)
{
    //s1 of pseudo -> s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    string rr17 = rotateRight(message, 17);
    string rr19 = rotateRight(message, 19);
    string right10 = goRight(message, 10);

    return (std::bitset<32>(rr17) ^ std::bitset<32>(rr19) ^ std::bitset<32>(right10)).to_string();
}

string SHA256::s2(string message)
{
    //2nd s1 of pseudo -> S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
    string rr6 = rotateRight(message, 6);
    string rr11 = rotateRight(message, 11);
    string rr25 = rotateRight(message, 25);

    return (std::bitset<32>(rr6) ^ std::bitset<32>(rr11) ^ std::bitset<32>(rr25)).to_string();
}

string SHA256::s3(string message)
{
    //2nd s0 of pseudo -> S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
    string rr2 = rotateRight(message, 2);
    string rr13 = rotateRight(message, 13);
    string rr22 = rotateRight(message, 22);

    return (std::bitset<32>(rr2) ^ std::bitset<32>(rr13) ^ std::bitset<32>(rr22)).to_string();
}

string SHA256::displayHash()
{
    return this->messageHash;
}

string SHA256::displayOG_Message()
{
    return this->message;
}
