

service Cpabe{
	
	binary getMessage(1:string uid, 2:string update_time, 3:list<string> attrs);
	bool  setMessage(1:binary msg);

}
