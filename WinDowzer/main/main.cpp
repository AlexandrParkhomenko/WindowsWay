#include <stdio.h>
#include <windows.h>
int main(int arg,char* argv[]){
	HWND hWnd;
	if(arg>2) {
		sscanf(argv[1], "0x%08x",&hWnd);
		LRESULT rret = SendMessage(hWnd,WM_SETTEXT,0,(LPARAM) argv[2]);
		if(rret!=NULL){
		} else {
		printf("SendMessage error\n");
		}
		/*
		HWND ret = SetActiveWindow(hWnd);
		if(ret!=NULL){
		} else {
		printf("SetActiveWindow error\n");
		}
		*/
		BOOL bret = SetWindowText(hWnd, (LPCTSTR) argv[2]);
		if(bret==FALSE) printf("SetWindowText error\n");
	} else {
		printf("some error\n");
	}
	
	return 0;
}