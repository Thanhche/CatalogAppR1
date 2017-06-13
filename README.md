## Linux Server Configuration

This guide displays step-by-step how to setup a Virtual Private Server(VPS) and public a web appliaction to internet on the Linux server.

#### IP Address (Provided by VPS): 138.68.237.243

#### Web Address: http://138.68.237.243

#### GitHub repo: https://github.com/Thanhche/CatalogApp

#### Reference Sources:

	- Udacity Lessons: Linux Server Configuration

	- Udacity Forums

	- https://www.digitalocean.com/community/tutorials

	- https://www.digitalocean.com/community/tutorials/how-to-deploy-a-flask-application-on-an-ubuntu-vps

    - https://cloud.digitalocean.com/droplets/

    - StackOverflow

    - https://www.digitalocean.com/community/tutorials/how-to-secure-postgresql-on-an-ubuntu-vps

    - https://www.postgresql.org/docs/9.0/static/sql-alterrole.html

    - https://www.postgresql.org/docs/8.0/static/sql-createuser.html

    - https://www.postgresql.org/docs/9.0/static/sql-createdatabase.html

    - http://askubuntu.com/questions/323131/setting-timezone-from-terminal

#### Packages Will Be Installed:

	- Apache2: the most commonly used Web server on Linux systems, where hosts my web application.

    - PostgreSQL: creates the database to store all app data.

	- SQLAlachemy: maps relational databases into objects. It manages an applications database connections. It can create/alter a database layout.

	- Virtualenv:  is a tool to create isolated Python environments. virtualenv creates a folder which contains all the necessary executables to use the packages.

	- Git: uses to directly clone the project from Git to the server.
	- Flask: Flask is a web framework, provides tools, libraries and technologies that allow you to build a web application.
	- oAuth 2: authenticates all login activities via google and facebook.

## Setup

### Create user `grader` with root access:

1. ssh connects to server via the root user using the provided rsa key, prompt below:

    -   `root@ubuntu-512mb-sfo2-01:~#`

2. Create a new user `grader`:

	- `adduser grader`

		- Input strong password and some options

3. Give `grader` the root access by creating a config file in sudoers.d directory:

	- `sudo nano /etc/sudoers.d/grader`

4. Add the following line:

	- `grader ALL=(ALL) ALL`

	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

5. Switch to the `grader` user:

	- `su - grader`

The prompt changes to: `grader@ubuntu-512mb-sfo2-01:~#`

6. Update installed packages to the most recent versions:

	- `sudo apt-get update`

	- `sudo apt-get upgrade`

### Configure Key-Based Authentication:

1. On the local machine, run the folowing command to generate a new rsa key for `grader.` For name and location, use: `/root/.ssh/grader`

	- `ssh-keygen`

2. Open file grader.pub and copy all content:

    - `cat .ssh/grader.pub`

3. Change to terminal `grader` user, create a new directory .ssh then create authorized_keys file for the public key:

    - `su - grader`

	- `mkdir .ssh`

	- `sudo nano .ssh/authorized_keys`

and paste copied content.
	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

4. Configure the permissions to allow access

	- `cd`

	- `sudo chmod 700 .ssh`

	- `sudo chmod 644 .ssh/authorized_keys`

5. Close the connection and then reconnect using the rsa key

	- `exit`

	- `ssh grader@138.68.237.243 -i ~/.ssh/grader`

    Now, `grader` user can work with `sudo`

### Configure ssh Settings:

1. Open the ssh config file:

	- `sudo nano /etc/ssh/sshd_config`

2. Make the following changes:


	- change `Port 22` to `Port 2200` [Access server through port: 2200]

	- change `PermitRootLogin yes` to `PermitRootLogin no`  [Cannot log in as root remotely]

	- change `PasswordAuthentication yes` to `PasswordAuthentication no` [Login remotely must use key_based]

	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

3. Restart ssh service to take affect:

	- `sudo service ssh restart`

4. Exit the the connection and re-connect using port 2200:

	- `exit`

	- `ssh grader@138.68.237.243 -i ~/.ssh/grader -p 2200`

### Configure the Firewall

1. Deny all incomings and allow all outgoings in default:

	- `sudo ufw default allow outgoing`

	- `sudo ufw default deny incoming`

2. Allow ports for SSH(port:2200), HTTP(port:80), and NTP(port:123):

	- `sudo ufw allow 2200`

    - `sudo ufw allow 80`

	- `sudo ufw allow 123`

3. Active the firewall:

	- `sudo ufw enable`

4. Review and verify the firewall configs by following command:

    - `sudo ufw status`

### Configure Timezone to UTC

1. Execute the following command:

	- `sudo dpkg-reconfigure tzdata`

2. Scroll down the bottom and select `None of the above`

3. Scroll down and select `UTC`

### Configure The Server

1. Install Apache 2 and the WSGI plugin:

	- `sudo apt-get install apache2`

	- `sudo apt-get install libapache2-mod-wsgi python-dev`

	- `sudo apt-get install python-setuptools`

	- `sudo a2enmod wsgi`

2. Create the new directories for my application:

	- `sudo mkdir /var/www/catalog`

	- `sudo mkdir /var/www/catalog/catalog`

3. Move into the directory and create a new file of python coding:

	- `cd /var/www/catalog/catalog`

	- `sudo nano __init__.py`

4. Create a simple 'Hello World' program to ensure everything work okay:

		from flask import Flask
		app = Flask(__name__)
		@app.route("/")
		def hello():
		    return "Hello World, I am going to come!"
		if __name__ == "__main__":
			app.run()

	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

5. Install pip and virtualenv:

	- `sudo apt-get install python-pip`

	- `sudo pip install virtualenv`

6. Create a new virtual environment then run it:

	- `sudo virtualenv temp_env`

	- `source temp_env/bin/activate`

7. Install Flask then run flask app by python:

	- `sudo pip install Flask`

	- `sudo python __init__.py`

8. If everything is working correctly, the terminal will display: `Running on http://localhost:5000/`

	- <kbd>ctrl</kbd>+<kbd>C</kbd>

9. Exit Virtualenv mode:

	- `deactivate`

10. Create the new application config file, add the following code, and then enable the app:

	- `sudo nano /etc/apache2/sites-available/catalog.conf`

			<VirtualHost *:80>
	            ServerName 138.68.237.243
	            ServerAdmin admin@138.68.237.243
	            WSGIScriptAlias / /var/www/catalog/catalog.wsgi
	            <Directory /var/www/catalog/catalog/>
	                    Order allow,deny
	                    Allow from all
	            </Directory>
	            Alias /static /var/www/catalog/catalog/static
	            <Directory /var/www/catalog/catalog/static/>
	                    Order allow,deny
	                    Allow from all
	            </Directory>
	            ErrorLog ${APACHE_LOG_DIR}/error.log
	            LogLevel warn
	            CustomLog ${APACHE_LOG_DIR}/access.log combined
			</VirtualHost>

	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

	- `sudo a2ensite catalog`

	- `service apache2 reload`

11. Create the wsgi file and add the following code:

	- `cd /var/www/catalog`

	- `sudo nano catalog.wsgi`

			#!/usr/bin/python
			import sys
			import logging
			logging.basicConfig(stream=sys.stderr)
			sys.path.insert(0,"/var/www/catalog/")

			from catalog import app as application
			application.secret_key = 'something'

	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

12. Restart apache2:

	- `sudo service apache2 restart`

13. Input the URL address: http://138.68.237.243 in the web browser and the page displays `Hello World, I am going to come!`

### Install and setup PostgreSQL to create the database

1. Move to the virtual enviornment and activate it:

	- `cd /var/www/catalog/catalog`

	- `source temp_env/bin/activate`

2. Install PostgreSQL, SQLalchemy and python-psycopg2:

	- `sudo apt-get install postgresql`

	- `sudo pip install sqlalchemy`

	- `sudo apt-get install python-psycopg2`

3. When PostgreSQL is installed, switch to user `postgres` and start PostgreSQL commands:

	- `sudo -u postgres psql`

4. Now, we are in the Postgres engine. We create a database `tutor` with the user `catalogitem` and password `choxutimeo`:

	- `CREATE USER catalogitem WITH PASSWORD 'choxutimeo';`

	- `ALTER USER catalogitem CREATEDB;`

	- `CREATE DATABASE tutor WITH OWNER catalogitem;`

5. Grant new user and revoke public access to database:

	- `REVOKE ALL ON SCHEMA public FROM public;`

	- `GRANT ALL ON SCHEMA public TO catalogitem;`

### Install Git and clone the coding from Github

1. Install Git and Clone the application from git:

	- `sudo apt-get install git`

	- `cd /var/www/catalog`

	- `sudo git clone https://github.com/Thanhche/CatalogItemApp.git`

	- `sudo mv /var/www/catalog/CatalogItemApp/* /var/www/catalog/catalog`

2. Rename the main python file `app.py` to `__init__.py`:

	- `sudo mv /var/www/catalog/catalog/app.py /var/www/catalog/catalog/__init__.py`

3. Change from SQlite to PostgreSQL engine:

	a. Open file `database_setup.py` and make the following change:

	- `cd /var/www/catalog/catalog`

	- `sudo nano database_setup.py`

	- change:

			engine = create_engine('sqlite:///categorymenu.db')

	- to:

			engine = create_engine("postgresql://catalogitem:choxutimeo@localhost/tutor")

	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

	b. Make the similar in the `__init__.py` file:

	- `sudo nano __init__.py`

	- change:

			engine = create_engine('sqlite:///categorymenu.db')

	- to:

			engine = create_engine("postgresql://catalogitem:choxutimeo@localhost/tutor")

	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

4. Install packages were using in __init__.py: httplib2, request and oauth2client

	- `sudo pip install httplib2`

	- `sudo pip install requests`

	- `sudo pip install oauth2client`

5. Create the database:

	- `sudo python database_setup.py`

6. Add records to the database:

    - `sudo python menus.py`

7. Edit the client_secrets.json, fb_client_secrets.json:

	- `cd /var/www/catalog/catalog`

	- `sudo nano client_secrets.json`

		Copy/paste your client secrets from google: https://console.cloud.google.com/apis/credentials?project=myrestaurant-158722
	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

	- `sudo nano fb_client_secrets.json`

		Copy/paste your client secrets from facebook.

	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

8. Edit the __init__.py file for matching the new path:

	- `nano __init__.py`

	- change:

			CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

	- to:

			CLIENT_ID = json.loads(open('/var/www/catalog/catalog/client_secrets.json', 'r').read())['web']['client_id']

	- change:

			oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')

	- to:

			oauth_flow = flow_from_clientsecrets('/var/www/catalog/catalog/client_secrets.json', scope='')

	- change:

			app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']

			to

			app_id = json.loads(open('/var/www/catalog/catalog/fb_client_secrets.json', 'r').read())['web']['app_id']

	- change:

			app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']

	- to:

			app_secret = json.loads(open('/var/www/catalog/catalog/fb_client_secrets.json', 'r').read())['web']['app_secret']

9. To ensure everything is correctly, Run `__init__.py` file:

	- `sudo python __init__.py`

	If everything is good, you should see `* Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)`

	- <kbd>ctrl</kbd>+<kbd>C</kbd>

10. Exit Virtualenv mode:
	- `deactivate`

11. Log into the google and facebook developers console and add your new web address to the accepted list of orgins and redirects.

12. Add the web domain to the `catalog.conf` file:

	- `sudo nano /etc/apache2/sites-available/catalog.conf`

	- add `ServerAlias server` directly under the line `ServerAdmin admin@138.68.237.243`

	- save <kbd>ctrl</kbd>+<kbd>O</kbd> and exit <kbd>ctrl</kbd>+<kbd>X</kbd>

13. Prevent file indexing from a web browser:

	- `sudo a2dismod autoindex`

14. Restart apache2:

	- `sudo service apache2 restart`

15. Run the web:

	- In a web browser, run the new website!  `http://138.68.237.243`

16. Check the error.log file if has any error message:

	- `sudo cat /var/log/apache2/error.log`
