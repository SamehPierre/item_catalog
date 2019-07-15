# Computer Catalog

This a Udacity [Full Stack Nanodegree](https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004) project Item Catalog.
The website offers a various of Laptops brands with description for each laptop model. 
Users can Log in via Google authentication (Add, modify and delete) their products.

### Prerequisites and Tools
* [Python 3](https://www.python.org/downloads/).
* [Vagrant](https://www.vagrantup.com/).
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads).
* [Sqlalchemy](https://www.sqlalchemy.org/download.html).

* The following Python packages: 
  - oauth2client
  - requests
  - httplib2
  - flask
 * You may need to install some other modules if the application threw module-not-found error. Do this by running `pip install --user` inside vagrant.

## Running the project
* Clone the _**Vagrantfile**_ from Udacity [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm) repo.
* **From the terminal**, run `vagrant up` to run the virtual machine, then `vagrant ssh` to login to the VM.
* cd to the project directory.
* Setup the database by running `python3 database_setup.py`.
* Populate the database by running `python3 populate.py`.
* Type `python3 project.py` to run the Flask web server.
* visit  http://localhost:8000/ in your browser to access the Computer Catalog app.

**The project contain the database you can use it without the use of setup. The database name is  `ComputerShop.db`.**
