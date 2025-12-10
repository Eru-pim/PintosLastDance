/* lazy_test.c */
#include <stdio.h>
#include <syscall.h>

/* * 1. 실행 파일의 크기를 뻥튀기하기 위한 거대한 배열 
 * 초기화된 데이터(1로 채움)라 .data 섹션에 들어가서 실제 파일 용량을 차지함.
 * 약 1MB 크기 (Pintos 환경에서는 꽤 큰 편)
 */
char huge_data[1024 * 1024] = {1, }; 

int main (void) 
{
    /* * 2. 아무것도 하지 않음!
     * 거대한 데이터를 선언만 했지, 실제로는 건드리지 않고 바로 종료함.
     */
    printf("Lazy Loading Test: I did nothing and exited!\n");
    return 0;
}