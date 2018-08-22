/**
* @file     FuncCS.cpp
* @brief    choose a function
* @author   kaili
* @date     2018Äê4ÔÂ14ÈÕ14:17:47
* @version  A001
*/
#include <functions.h>
int funcCS()
{
    int choice=0;
    scanf("%d",&choice);
    switch(choice)
    {
        case 1: capture();break;
        case 2: send();break;
        default : printf("Error!\n");return 0;
    }
}
