# Database Readme

Simple readme for how to use the tinyDB database. Full documentation avaialable from here:
`https://tinydb.readthedocs.io/`

## Setup and Usage

In the file you are using, make sure you import the database:
```
import database
```

Then define the database:
```
db = database.db()
```
There are 3 different tables for each threat:
```
self.brute_force_table 
self.blacklist_table
self.multi_login_table
```
You can insert rows via the insert into your desired table:
```
db.blacklist_table.insert({'id': 12345678, 'time': '09/02/20 12:30', 'threat_level': 'high', 'message': '20 failed log in attempts'})
```

You can search for user id by:
```
db.blacklist_table.search(tinydb.where('id') == 12345678)
```