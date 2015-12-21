#include<stdio.h>
void test()
{
	char a[40];
	while(1)
	{

		printf("please input:");
		fgets(a,40,stdin);
		if(!strcmp(a,"exit\n"))
			break;
		printf("your input is ");
		printf(a);
	}
}
int main()
{	setbuf(stdout,0);
	test();
	
}