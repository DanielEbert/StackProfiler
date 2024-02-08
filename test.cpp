#include <iostream>
#include <cstdio>
#include <cstring>


int main(int argc, char* argv[])
{
    if (argc > 1)
    {
        if (strcmp(argv[1], "hey") == 0)
        {
            std::cout << "huhu" << std::endl;
            return 0;
        }
    }

    return 1;
}

