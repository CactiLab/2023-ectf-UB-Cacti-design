//
//  main.m
//  RSAProject
//
//  Created by guozhicheng on 5/9/16.
//  Modified by Xi Tan on 02/16/2023
//  Copyright © 2023 guozhicheng, Xi Tan. All rights reserved.
//

#include "rsa_test.h"

int main(int argc, const char *argv[])
{
    int counter;
    char *p;
    if (argc >= 2)
    {
        int opt = strtol(argv[1], &p, 10);
        printf("argv[1]: %d\n", opt);

        switch (opt)
        {
        case 1:
            printf("Generate the key.\n");
            generateRSAKeys();
            break;
        case 2:
            printf("Sign the challenge.\n");
            break;

        default:
            testprint();
            break;
        }
    }
    else
    {
        testprint();
    }
    return 0;
}
