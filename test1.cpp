#include <iostream>
#include <string>
#include <fstream>
using namespace std;

#define GRN "\e[0;32m"
#define RED "\033[31m"
#define NC "\e[0m"
string udptype="UDP";
string gtptype="GTP";
string dnstype="DNS";//Todo:

// TEST tpoplagy: 
//  _________           _________           _________
//  |        |   GTP    |        |   UDP    |        |
//  |   RAN  |<-------->|   UPF  |<-------->|   DN   |
//  |________|          |________|          |________|
//
//  UL : GTP(intput) UDP(output)
//  DL : GTP(output) UDP(input)

string ip_udp[2]={"0","0"};
string ip_gtp[4]={"0","0","0","0"};
string zero("0");
int udp_pknum=0;
int gtp_pknum=0;


int udp_pk_analyze(int flag){
	
	fstream file;
	if (flag==1){//UL ==> output
        	file.open("typeout.txt", fstream::in);//in order to check the type,and count the right packet number
	}	
	else if(flag==0){//DL ==> input
		file.open("typein1.txt", fstream::in);
	}
	else{
	 	cout<<"\nflag error\n";
		return 0;
	}
	if(!file.is_open()){
                cout<< "No such file\n";
               	return 0;
       	}


	
       	string a[100];
        int count=0;
       	while(!file.eof()) {
                getline(file,a[count],'\n');
               	count++;
       	}
      	file.close();

        //Cut the string to get UDP packet number
       	int countpk=0;
       	int pk_num[10];
        int y=0;
       	for(int i=0;i<count;i++){
             	//cout<<a[i]<<" # "<<i<<"\n";
               	string::size_type x=a[i].find(udptype);
               	if(x!=string::npos){
                       	countpk++;
                       	pk_num[y]=i;
                       	//cout<<pk_num[y]<<"\n";
                       	y++;
             	}
               	else{
                       	//cout <<"*";
               	}
       	}
	if(countpk>0){
               	cout<<"UDP packet number: "<<countpk<<"\n";
		udp_pknum=countpk;
       	}
       	else{
               	cout<<RED"There is no UDP packet receving from N6 UPF"<<NC"\n";
               	return 0;	
	}

	//Get ip information to check if it's right or not
	if (flag==1){//UL ==> output
		file.open("ipout.txt", fstream::in);
	}
	else if(flag==0){//DL ==> input
                file.open("ipin1.txt", fstream::in);
        }
	if(!file.is_open()){
                cout<< "No such file\n";
                return 0;
        }
	
	string b[100];
	int count1=0;
	while(!file.eof()) {
                getline(file,b[count1],'\n');
                //cout<<b[count1]<<"\n";
                count1++;
        }
        file.close();
	//cout<<"###"<<count1;
	string ip1;
        string ip2;
        for(int i=0;i<count1;i++){
                if(i==pk_num[0]){
                        int pos = b[i].find(",", 0);
                        if(pos != string::npos) {
                                ip1=b[i].substr(0,pos);
                                //cout<<"IP1 : "<<ip1<<"\n";
                                b[i]=b[i].substr(pos+1,b[i].length()-1);
                        }
                        else{
                                cout<<RED"Checking ip wrong"<<NC"\n";
                                return 0;
                        }
                        ip2=b[i];
                        //cout << "IP2 : " <<ip2<<"\n";
                }

        }
	if (flag==1){//UL ==> output
               	ip_udp[0]=ip1;
	       	ip_udp[1]=ip2;
		//cout<<ip1;
        }
        else if(flag==0){//DL ==> input
               	ip_udp[0]=ip2;
		ip_udp[1]=ip1;				
        }
	
	
}
int gtp_pk_analyze(int flag){
	fstream file1;
        if (flag==1){//UL ==> input
                file1.open("typein.txt", fstream::in);
        }
        else if(flag==0){//DL ==> output
                file1.open("typeout1.txt", fstream::in);

        }
        else{
                cout<<"\nflag error\n";
                return 0;
        }
	if(!file1.is_open()){
                cout<< "No such file\n";
                return 0;
        }

        string c[100];
        int count2=0;
        while(!file1.eof()) {
                getline(file1,c[count2],'\n');
		//cout<<" "<<c[count2]<<"\n";
		count2++;
        }
        file1.close();
	
	//Cut the string to get UDP packet number
        int countpk=0;
        int pk_num[10];
        int y=0;
        for(int i=0;i<count2;i++){
                //cout<<c[i]<<" # "<<i<<"\n";
                string::size_type x=c[i].find(gtptype);
                if(x!=string::npos){
                        countpk++;
                        pk_num[y]=i;
                        //cout<<pk_num[y]<<"\n";
                        y++;
                }
                else{
                        //cout <<"*";
                }
        }
        if(countpk>0){
                cout<<"\nGTP packet number: "<<countpk<<"\n";
		gtp_pknum=countpk;
        }
        else{
                cout<<RED"There is no GTP packet receving from N6 UPF"<<NC"\n";
                return 0;
        }
	
	if (flag==1){//UL ==> output
                file1.open("ipin.txt", fstream::in);
        }
        else if(flag==0){//DL ==> input
                file1.open("ipout1.txt", fstream::in);
        }
        if(!file1.is_open()){
                cout<< "No such file\n";
                return 0;
        }
	
	string d[100];
        int count3=0;
        while(!file1.eof()) {
                getline(file1,d[count3],'\n');
                //cout<<d[count1]<<"\n";
                count3++;
        }
        file1.close();


        //cout<<"###"<<count1;
        string ip3;
        string ip4;
	string ip5;
        string ip6;
        for(int i=0;i<count3;i++){
                if(i==pk_num[0]){
                        int pos = d[i].find(",", 0);
                        if(pos != string::npos) {
                                ip3=d[i].substr(0,pos);
                                //cout<<"IP3 : "<<ip3<<"\n";
                                d[i]=d[i].substr(pos+1,d[i].length()-1);
				pos = d[i].find(",", 0);
				ip4=d[i].substr(0,pos);
				d[i]=d[i].substr(pos+1,d[i].length()-1);
				pos = d[i].find(",", 0);
                                ip5=d[i].substr(0,pos);
                                d[i]=d[i].substr(pos+1,d[i].length()-1);
                        }
                        else{
                                cout<<RED"Checking ip wrong"<<NC"\n";
                                return 0;
                        }
                        ip6=d[i];
			//cout << "IP4 : " <<ip4<<"\n";
			//cout << "IP5 : " <<ip5<<"\n";
                        //cout << "IP6 : " <<ip6<<"\n";
                }

        }
	if (flag==1){//UL ==> output
                ip_gtp[0]=ip4;//UE
                ip_gtp[1]=ip6;//DN
		ip_gtp[2]=ip3;//RAN
                ip_gtp[3]=ip5;//UPFN3
                //cout<<ip1;
        }
        else if(flag==0){//DL ==> input
                ip_gtp[0]=ip6;//UE
                ip_gtp[1]=ip4;//DN
		ip_gtp[2]=ip5;//RAN
                ip_gtp[3]=ip3;//UPFN3
        }


}
int checkpknum(){
	//udp_pknum=0;
	if(udp_pknum==0){
		cout<<RED"\nUDP packet number wrong"<<NC"\n";
		return 0;
	}
	if(gtp_pknum==0){
                cout<<RED"\nGTP packet number wrong"<<NC"\n";
		return 0;
        }
	if(udp_pknum!=gtp_pknum){
		cout<<RED"\nSome packets lose"<<NC"\n";
	}

}
int compare_ip(int flag){
	if(ip_gtp[0]==""||ip_gtp[1]==""||ip_gtp[2]==""||ip_gtp[0]==""||ip_udp[0]==""||ip_udp[1]==""){
	  	cout<<RED"\n\nCould no find ip\n"<<NC"\n";
		return 0;
	}//if lose any information in pcap,it will return fail
	
	int res,res1; 
	res=ip_gtp[0].compare(ip_udp[0]);
	res1=ip_gtp[1].compare(ip_udp[1]);
	if(res==0&&res1==0){
                cout<<GRN"\nTest IP : PASS"<<NC"\n";
        }
	else{
		cout<<RED"\nTest IP : Fail"<<NC"\n";
	}


}
int compare_qfi(){
	fstream file2;
        file2.open("dlqfi.txt", fstream::in);
        if(!file2.is_open()){
                cout<< "No such file\n";
                return 0;
        }

        string e[100];
        int count3=0;
        while(!file2.eof()) {
                getline(file2,e[count3],'\n');
                //cout<<" "<<e[count3]<<"\n";
                count3++;
        }
        file2.close();
	string n4_qfi;
	int y=count3-2;
	//cout<<e[y].length();
	for(int i=0;i<e[y].length();i++){
		//cout<<e[y][i];
		if(isdigit(e[y][i])){
		  	//cout<<"\n"<<e[y][i]<<"\n";
		  	n4_qfi=e[y][i];
	  	  	//cout<<n4_qfi;
		}
	}

	file2.open("dlqfi_n3.txt", fstream::in);
        if(!file2.is_open()){
                cout<< "No such file\n";
                return 0;
        }

        string f[100];
        int count4=0;
        while(!file2.eof()) {
                getline(file2,f[count4],'\n');
                //cout<<" "<<f[count4]<<"\n";
                count4++;
        }
        file2.close();
	
	string n3_qfi;
        int z=count4-2;
        //cout<<f[z].length();
        for(int i=0;i<f[z].length();i++){
                //cout<<e[z][i];
                if(isdigit(f[z][i])){
                        //cout<<"\n"<<f[z][i]<<"\n";
                        n3_qfi=f[z][i];
                        //cout<<"\n@@@"<<n3_qfi;
                }
        }
	
	int res;
        res=n3_qfi.compare(n4_qfi);
       
        if(res==0){
                cout<<GRN"Test QFI : PASS"<<NC"\n";
        }
        else{
                cout<<RED"Test QFI : Fail"<<NC"\n";
        }


}

int enter_traffic_direction(){ //Choose UL or DL
	//cout<<"enter ul or dl:\n";
        char traffic_type[2];
	int flag=2;
        while(1){
                cin>>traffic_type;
                if(traffic_type[0]=='u'&& traffic_type[1]=='l'){
                        cout<<traffic_type<<"\n";
			flag=1;
			return flag;
                }
                else if(traffic_type[0]=='d'&& traffic_type[1]=='l'){
                        cout<<traffic_type<<"\n";
			flag=0;
			return flag;
                }
                else{
                        cout<<"error, enter again\n";
                }
        }
	
}


int main(){
	int flag;
	flag=enter_traffic_direction();
       	//cout<<"flag : "<<flag;
	if(flag==1||flag==0){}
	else{
		cout<<"system wrong";
		return 0;
	}
	

	udp_pk_analyze(flag);
        cout<<"\nUE IP : "<<ip_udp[0];
        cout<<"\nDN IP : "<<ip_udp[1];
        gtp_pk_analyze(flag);
        cout<<"\nUE IP : "<<ip_gtp[0];
        cout<<"\nDN IP : "<<ip_gtp[1];
        cout<<"\nRAN IP : "<<ip_gtp[2];
        cout<<"\nUPF_N3 IP : "<<ip_gtp[3]<<"\n";
        
	int check=1;
	check=checkpknum();
	if (check==0){
		return 0;
	}

        compare_ip(flag);
	if(flag==0){
		compare_qfi();
	}
}
