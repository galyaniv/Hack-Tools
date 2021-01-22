// SumPrimeNumbers.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <iostream>
DWORD WINAPI calcPrime(PVOID Data);
int isPrime(int number);

struct threadData
{
    int first, end;
    int sum;
    DWORD threadId;
};

int main()
{
    int start = 0;
    int end = 20000;
    int numberOfThreads = 8;
    int sumOfNumbersToCalc = floor((end-start) / numberOfThreads) - 1;
    DWORD threadId;
    threadData Data [8];
    HANDLE threadsList[8];
    for (int i = 0; i < numberOfThreads; i++)
    {
        Data[i].first = start;
        if (i == 0) {
            Data[i].end = start + sumOfNumbersToCalc + (end - start) % numberOfThreads;
            start += (end - start) % numberOfThreads;
        }
        else {
            Data[i].end = start + sumOfNumbersToCalc;
        }
        Data[i].sum = 0;
        HANDLE hThread = CreateThread(NULL, 0, calcPrime, &Data[i], 0, &threadId);
        if (hThread != INVALID_HANDLE_VALUE) {
            threadsList[i] = hThread;
            Data[i].threadId = threadId;
        }
        else {
            printf("[+] Error occurred while creating thread\n");
            continue;
        }
        printf("[+] Thread %d was created!\n", threadId);
        start += (sumOfNumbersToCalc + 1);
    }
    WaitForMultipleObjects(8, threadsList, TRUE, INFINITE);
    printf("\n\n\n");

    int totalSum = 0;
    for (int n = 0; n < numberOfThreads; n++)
    {
        printf("[+] Sum thread %d is %d\n",n, Data[n].sum);
        totalSum += Data[n].sum;
    }
    printf("[+] Total sum: %d", totalSum);

}

DWORD WINAPI calcPrime(PVOID Data) {
    threadData* tData = (threadData*)Data;
    printf("[+] Calculating sum of prime from %d to %d\n", tData->first, tData->end);
    for (int i = tData->first; i <= tData->end; i++)
    {
        if (isPrime(i)) {
            tData->sum += i;
        }
    }
    return 0;
}

int isPrime(int number) {
    if (number <= 1)
    {
        return FALSE;
    }
    else {
        int limit = (int)sqrt((float)number);
        for (int j = 2; j <= limit; j++) {
            if (number % j == 0) {
                return FALSE;
            }
        }
        return TRUE;
    }
}
