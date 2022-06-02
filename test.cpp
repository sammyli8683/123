#include <iostream>
#include <string>
#include <fstream>
using namespace std;

string udptype="UDP";
string gtptype="GTP";
string dnstype="DNS";


int ul_ipcheck(int pk_num[10], int pk_count){
	//check the output packets by comparing with input packets 
  	fstream file;
        file.open("ipout.txt", fstream::in);
        if(!file.is_open()){
                cout<< "No such file\n";
                return 0;
        }
        string a[100];
        int count=0;
        while(!file.eof()) {
                getline(file,a[count],'\n');
		//cout<<a[count]<<"\n";
                count++;
        }
        file.close();
 	
	string ue_ip;
	string dn_ip;	
	for(int i=0;i<count;i++){
		if(i==pk_num[0]){
			int pos = a[i].find(",", 0);
			if(pos != string::npos) {
				ue_ip=a[i].substr(0,pos);
				cout<<"UE IP : "<<ue_ip<<"\n";
				a[i]=a[i].substr(pos+1,a[i].length()-1);
			}
			else{
				cout<<"Part of checking ip wrong";
				return 0;
			}
		        dn_ip=a[i];
			cout << "DN IP : " <<dn_ip<<"\n";	
		}
	
	}
}

int ul_check(){
	fstream file;
	file.open("typeout.txt", fstream::in);//in order to check the type,and count the right packet number
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

 
	if(countpk>0){//if the packet type is right
		cout<<"UDP packet number: "<<countpk<<"\n";
		ul_ipcheck(pk_num,countpk);
	}
	else{
                cout<<"There is no UDP packet receving from N6 UPF\n";
		return 0;
        }
		
}
int dl_check(){//check CL packet

}

int enter_traffic_direction(){ //Choose UL or DL
	cout<<"enter ul or dl:\n";
        char traffic_type[2];
        while(1){
                cin>>traffic_type;
                if(traffic_type[0]=='u'&& traffic_type[1]=='l'){
                        //cout<<traffic_type<<"\n";
			ul_check();
			break;
                }
                else if(traffic_type[0]=='d'&& traffic_type[1]=='l'){
                        //cout<<traffic_type<<"\n123\n";
                        dl_check();
			break;
                }
                else{
                        cout<<"error, enter again\n";
                }
        }
	
}
int main(){
	enter_traffic_direction();
	
}
