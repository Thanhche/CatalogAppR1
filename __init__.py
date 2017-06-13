import re
import random
import string
import httplib2
import json
import requests
import hashlib
import urllib2
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, MenuItem, User
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response
from string import letters


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Item Application"


# Connect to Database and create database session
engine = create_engine("postgresql://catalogitem:choxutimeo@localhost/tutor")
# engine = create_engine('sqlite:///categorymenu.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Input content, the global variable
search_input=''

# List of categories have accsess
# Reset this global var to []
category_access_list=[]
def add_category_access_list(item_id):
    global category_access_list
    if item_id not in category_access_list:
        category_access_list.append(item_id)

# List of items have accsess
# Reset this global var to []
item_access_list=[]
def add_item_access_list(item_id):
    global item_access_list
    if item_id not in item_access_list:
        item_access_list.append(item_id)

# The list of all categories
def categorynameList():
    categoryName_List=[]
    categories = session.query(Category).all()
    for category in categories:
        categoryName_List.append(category.name)
    return categoryName_List

# The list of all menu items
def menuitemList():
    menuItem_List=[]
    menuitems = session.query(MenuItem).all()
    for menuitem in menuitems:
        menuItem_List.append(menuitem.name)
    return menuItem_List

# User and password *************************
# Make a random 5 characters string
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Encrypting name, password with salt
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# Verify name, password when log in
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# End User and password *********************


# Validate the name input
def valid_name(name):
    result = {}
    USER_RE = re.compile(r"^[a-z\s\'\.!@#$%&A-Z0-9_-]{3,30}$")

    if USER_RE.match(name):
        result = {}
    elif len(name) > 30:
        result['name_length'] = "Name length exceeds 30"
    else:
        result['name'] = "Invalid letters"

    return result


# Validate the description input
def valid_description(description):
    result = {}
    DESCRIPTION_RE = re.compile(r"[a-z\s\'\.\,!/-@#$%&A-Z0-9_-]{1,200}$")

    if DESCRIPTION_RE.match(description):
        result = {}
    elif len(description) > 200:
        result['description_length'] = "The length exceeds 200"
    else:
        result['description'] = "Invalid letters"

    return result


# Validate the price input
def valid_price(price):
    result = {}
    PRICE_RE = re.compile(r"[\d]{1,5}\.[\d]{1,2}$")

    if PRICE_RE.match(price):
        result = {}
    else:
        result['price'] = "Invalid price, format: xxx.xx"

    return result


# Validate the password input
def valid_password(password):
    result = {}
    PASS_RE = re.compile(r".{3,20}$")

    if PASS_RE.match(password):
        return {}

    elif len(password) > 30:
        result['password_length'] = "The length exceeds 30"
    else:
        result['password'] = "Invalid letters"

    return result

# Validate the email input
def valid_email(email):
    EMAIL_RE = re.compile(r'[\S]+@[\S]+\.[\S]+$')
    if EMAIL_RE.match(email):
        return email


def count_mismatch(s1,s2):

    if len(s1) != len(s2):
        return 2

    s1=s1.lower()
    s2=s2.lower()

    number_of_mismatches=0

    for index in range(len(s1)):
        if s1[index] != s2[index]:
            number_of_mismatches += 1
            if number_of_mismatches>1:
                return 2
    return number_of_mismatches


def single_fix(s1,s2):

    # Source string
    s1=s1.lower()

    # Destination string
    s2=s2.lower()

    if s1==s2:
        return 0

    if abs(len(s1)-len(s2))!=1:
        return 2

    if len(s1)>len(s2):
        # delete only one different character then verify
        for k in range(len(s2)):

            if s1[k]!=s2[k]:
                if s1[k+1:]==s2[k:]:
                    return 1
                else:
                    return 2
        return 1

    else: # s1 is shorter Only insertion is possible
        for k in range(len(s1)):
            if s1[k]!=s2[k]:
                if s1[k:]==s2[k+1:]:
                    return 1
                else:
                    return 2
        return 1


# Open the About page
@app.route('/about')
def about():

    try:
        return render_template('about.html',
                                email_user=login_session['email'])
    except:
        return render_template('about.html')


# Open the allusers page
@app.route('/users')
def allusers():

    users = session.query(User).all()

    try:
        return render_template('allusers.html',
                                users=users,
                                email_user=login_session['email'])
    except:
        return render_template('allusers.html',
                                users=users)

# Create anti-forgery state token
@app.route('/login')
def showLogin():

    # Reset the caregory access list var
    global category_access_list
    global item_access_list
    category_access_list = []
    item_access_list = []

    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html',
                            STATE=state,
                            hideLogin=True,)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']

    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]
    login_session['name'] = data['name']

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

# gconnect
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    #data = answer.json()
    data = json.loads(answer.text)

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['name'] = data['name']
    #******************************
    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    #******************************
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Logged in as %s" % login_session['email'])
    print "done!"
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['name'],
                    email=login_session['email'],
                    pw_hash=login_session['pw_hash'],
                    picture=login_session['picture'])

    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Category Helper Functions
def getCategoryID(name):
    try:
        category = session.query(Category).filter_by(name=name).one()
        return category.id
    except:
        return None

def getCategoryInfo(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    return category

def getCategoryName(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    return category.name

# Menuitem Helper Functions
def getMenuitemID(name):
    try:
        menuitem = session.query(MenuItem).filter_by(name=name).one()
        return [name, menuitem.category_id]
    except:
        return None

def getMenuitemInfo(item):
    menuitem = session.query(MenuItem).filter_by(name=item[0], category_id=item[1]).one()
    return menuitem

# return a list of item names with a specific category name
def ItemNamesinCategory(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(MenuItem).filter_by(category_id=category.id).all()
    return [i.name for i in items]


# return a list of categories
def ListAllCategories():
    categories = session.query(Category)
    return [i.name for i in categories]


# This can be replace with /gdisconnect
@app.route('/clear')
def clearSession():
    login_session.clear()
    return "Login Session cleared"


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Category Information
# List all menu items in database
@app.route('/items.json')
def ItemsJSON():
    items = session.query(MenuItem).all()
    return jsonify(MenuItem=[i.serialize for i in items])


# JSON endpoint: List all latest menu_items
@app.route('/json')
@app.route('/latest.json')
def newItemJSON():
    items = session.query(MenuItem).filter_by(kind="new").all()
    return jsonify(MenuItem=[i.serialize for i in items])


# JSON APIs to view Category Information
@app.route('/categories.json')
def CategoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[i.serialize for i in categories])


# JSON endpoint: List all users who's in database
@app.route('/users.json')
def UserJSON():
    users = session.query(User).all()
    return jsonify(Users=[i.serialize for i in users])


# JSON endpoint: Lists all menu_items with specified category's name
@app.route('/catalog/<string:category_name>/items.json')
def CategoryNameItemsJson(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(MenuItem).filter_by(category_id=category.id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


# JSON endpoint: Lists all menu_items with specified category_id
@app.route('/catalog/<int:category_id>/items.json')
def categoryIdMenuJSON(category_id):
    items = session.query(MenuItem).filter_by(category_id=category_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


# JSON endpoint: List contents of a menu_item has specified
# category_name and item_id
@app.route('/catalog/<string:category_name>/<int:item_id>/item.json')
def menuItemJSON(category_name, item_id):
    category = session.query(Category).filter_by(name=category_name).one()
    menuItem = session.query(MenuItem).filter_by(category_id=category.id,
                                                 id=item_id).one()
    return jsonify(MenuItem=menuItem.serialize)


# JSON endpoint: List contents of a menu_item has specified
# category_id and item_id
@app.route('/catalog/<int:category_id>/<int:item_id>/item.json')
def menuidItemJSON(category_id, item_id):
    menuItem = session.query(MenuItem).filter_by(category_id=category_id,
                                                id=item_id).one()
    return jsonify(MenuItem=menuItem.serialize)


# JSON endpoint: List a menu_item has specified item_id
@app.route('/catalog/<int:item_id>/item.json')
def idItemJSON(item_id):
    menuItem = session.query(MenuItem).filter_by(id=item_id).one()
    return jsonify(MenuItem=menuItem.serialize)


# JSON endpoint: List all categories has specified user_id
@app.route('/category/<int:user_id>/user.json')
def categoryuserJSON(user_id):
    categories = session.query(Category).filter_by(user_id=user_id).all()
    return jsonify(categories=[i.serialize for i in categories])


# JSON endpoint: List all menu_items has specified user_id
@app.route('/menuitem/<int:user_id>/user.json')
def menuitemuserJSON(user_id):
    menuitems = session.query(MenuItem).filter_by(user_id=user_id).all()
    return jsonify(menuitems=[i.serialize for i in menuitems])

    '''
# List all categories and menu_items in public mode
@app.route('/catalog/<string:category_name>/items')
def categoryitemMenu(category_name):

    # Reset the category access list var
    #category_access_list = []

    # searching input content
    global search_input

    categories = session.query(Category)
    try:
        category = session.query(Category).filter_by(name=category_name).one()
        items = session.query(MenuItem).filter_by(category_id=category.id)
        return render_template('pub_categoryitem.html',
                                categories=categories,
                                category=category,
                                items=items,
                                category_name=category.name,
                                search_input=search_input)

    except:
        items = session.query(MenuItem).filter_by(kind="new").all()
        return render_template('pub_catalog.html',
                                categories=categories,
                                items=items,
                                search_input=search_input)

    '''
# Show the already menu_item's description when click on it's image
# in descriptionitem.html
@app.route('/catalog/<string:category_name>/<string:item_name>/desc', methods=['GET'])
def describeMenuItem(category_name, item_name):

    # searching input content
    global search_input

    if request.method == 'GET':

        category = session.query(Category).filter_by(name=category_name).one()
        menuItem = session.query(MenuItem).filter_by(category_id=category.id,
                                                    name=item_name).one()

        add_item_access_list(menuItem.id)
        add_category_access_list(category.id)


        if 'email' in login_session.keys():
            return render_template('descriptionitem.html',
                                    menuItem=menuItem,
                                    category=category,
                                    email_user=login_session['email'],
                                    search_input=search_input)

        else:
            return render_template('descriptionitem.html',
                                    menuItem=menuItem,
                                    category=category,
                                    search_input=search_input)

    else:
        if 'email' in login_session.keys():
            return redirect(url_for('seccategoryitemMenu',
                                    category_name=category_name,
                                    email_user=login_session['email'],
                                    cate_list=category_access_list,
                                    item_list=item_access_list))

        else:
            return redirect(url_for('categoryitemMenu',
                                    category_name=category_name))


# List all categories and latest menu_items in security mode
@app.route('/')
@app.route('/catalog')
@app.route('/seccatalog')
def seccatalogMenu():

    # searching input content
    global search_input

    global category_access_list
    global item_access_list

    if 'email' in login_session:
        email_user=login_session['email']
    else:
        email_user=''

    categories=session.query(Category)
    items=session.query(MenuItem).filter_by(kind="new").all()
    return render_template('sec_catalog.html',
                            categories=categories,
                            items=items,
                            email_user=email_user,
                            cate_list=category_access_list,
                            item_list=item_access_list,
                            search_input=search_input)


# List all category's menu_items in security mode
@app.route('/seccatalog/<string:category_name>/items')
def seccategoryitemMenu(category_name):

    # searching input content
    global search_input

    # The Lists of categories, items've accessed.
    global category_access_list
    global item_access_list

    if 'email' in login_session:
        email=login_session['email']
        userID=getUserID(email)
        user=getUserInfo(userID)
        username=user.name
    else:
        email=''
        userID=0
        user=None
        username=''

    categories = session.query(Category)


    if request.method=='GET':
        category = session.query(Category).filter_by(name=category_name).one()
        items = session.query(MenuItem).filter_by(category_id=category.id)

        # Add to category access list
        add_category_access_list(category.id)

        return render_template('sec_categoryitem.html',
                                categories=categories,
                                category=category,
                                items=items,
                                category_name=category.name,
                                email_user=email,
                                userID=userID,
                                username=username,
                                cate_list=category_access_list,
                                item_list=item_access_list,
                                search_input=search_input)


    else:
        items = session.query(MenuItem).filter_by(kind="new").all()
        return render_template('sec_catalog.html',
                                categories=categories,
                                items=items,
                                email_user=login_session['email'],
                                cate_list=category_access_list,
                                item_list=item_access_list,
                                search_input=search_input)


# Change the contents for an already menu_item
@app.route('/catalog/<string:category_name>/<string:item_name>/edit',
            methods=['GET', 'POST'])
def editMenuItem(category_name, item_name):

    # searching input content
    global search_input

    # Flash_str var
    FlashStr = ""

    # Reset the Errors var
    Errors = {}

    # Verify the log in status
    if 'email' not in login_session:
        return redirect('/login')

    # Retrieve user who is logging in
    user = session.query(User).filter_by(email=login_session['email']).one()

    # Retrieve category and edited item
    category = session.query(Category).filter_by(name=category_name).one()
    editedItem = session.query(MenuItem).filter_by(name=item_name, category_id=category.id).one()

    add_item_access_list(editedItem.id)

    # The item before edits
    before = editedItem

    # Conditions permits to edit an item
    if editedItem.user_id != user.id and user.name != 'admin':
        flash("Can not edit this item")
        return redirect(url_for('seccategoryitemMenu',
                                category_name=category_name))

    if request.method=='POST':

        # -------------Validate input----------------
        # Validate the name input
        Errors.update(valid_name(request.form['name']))

        # Validate the description input
        Errors.update(valid_description(request.form['description']))

        # Validate the price input
        Errors.update(valid_price(request.form['price']))

        # The name input is exist
        ListOfItems=ItemNamesinCategory(category.name)
        ListOfItems.remove(item_name) # remove it's name out off list
        if request.form['name'] in ListOfItems:
            Errors['double']='Name is exist'

        # Validate image
        image=request.form['image']

        # -----------------Flash string:--------------
        if not before.name == request.form['name']:
            FlashStr += "Item: " + before.name + " changed to " + request.form['name'] + " --- "

        if not before.price == request.form['price']:
            FlashStr += "Price: " + before.price + " changed to " + request.form['price'] + " --- "

        if not before.description == request.form['description']:
            FlashStr += " Description has changed --- "

        if not before.image == request.form['image']:
            FlashStr += " Image has changed --- "

        if not before.kind == request.form['kind']:
            FlashStr += " Kind has changed --- "

        if Errors=={}:
            flash(FlashStr)
            editedItem.name=request.form['name']
            editedItem.description=request.form['description']
            editedItem.price=request.form['price']
            editedItem.image=image
            editedItem.kind=request.form['kind']
            editedItem.category_id=category.id
            session.add(editedItem)
            session.commit()
            return redirect(url_for('seccategoryitemMenu',
                                    category_name=category_name))

        else:
            return render_template('editmenuitem.html',
                                    category_name=category_name,
                                    item_name=item_name,
                                    item=editedItem,
                                    email_user=login_session['email'],
                                    Errors=Errors,
                                    search_input=search_input)

    else:
        return render_template('editmenuitem.html',
                                category_name=category_name,
                                item_name=item_name,
                                item=editedItem,
                                email_user=login_session['email'],
                                Errors=Errors,
                                search_input=search_input)


# Change the contents for an already category
@app.route('/catalog/<string:category_name>/edit', methods=['GET', 'POST'])
def editCategory(category_name):

    # searching input content
    global search_input

    # Flash_str var
    FlashStr = ""

    # Reset the Errors var
    Errors = {}

    # The logged in status
    if 'email' not in login_session:
        return redirect('/login')

    # Retrieve the user and category to edit
    categoryEdit = session.query(Category).filter_by(name=category_name).one()
    user = session.query(User).filter_by(email=login_session['email']).one()

    # Conditions permits to edit a category
    if categoryEdit.user_id != user.id and user.name != 'admin':
        flash("Can not edit this category")
        return redirect(url_for('seccategoryitemMenu',
                                category_name=category_name))

    # The list of all categories
    categories_list = ListAllCategories()

    if request.method=='POST':

        # -------------Validate input----------------
        # Validate the name input
        Errors.update(valid_name(request.form['name']))

        # The name input is exist
        categories_list.remove(category_name)
        if request.form['name'] in categories_list:
            Errors['double']='Name is exist'

        # -----------------Flash string:--------------
        if not category_name == request.form['name']:
            FlashStr += "Category: " + category_name + " changed to " + request.form['name'] + " --- "

        if Errors=={}:
            flash(FlashStr)
            categoryEdit.name=request.form['name']
            categoryEdit.user_id=user.id
            session.add(categoryEdit)
            session.commit()
            return redirect(url_for('seccategoryitemMenu',
                                    category_name=categoryEdit.name))
        else:
            return render_template('editcategory.html',
                                   category_name=category_name,
                                   email_user=login_session['email'],
                                   Errors=Errors,
                                   search_input=search_input)

    else:
        return render_template('editcategory.html',
                                category_name=category_name,
                                email_user=login_session['email'],
                                Errors=Errors,
                                search_input=search_input)


# getCategoryID(name)
# getCategoryInfo(category_id)
# getMenuitemID(name)
# getMenuitemInfo(getMenuitemID(name))

# Searching the content in categories and menu items
@app.route('/catalog/<string:content>/search', methods=['GET', 'POST'])
def search(content):

    global search_input

    # List of all categories and menuitems in database
    categoryName_List=categorynameList()
    menuItem_List=menuitemList()

    # What's input
    search_input=''

    # User logged in
    if 'email' in login_session:
        email=login_session['email']
        userID=getUserID(email)
        user=getUserInfo(userID)
        username=user.name
    else:
        email=''
        userID=None
        username=''


    # List of category names menuitem names
    categories_container=[]
    menuitems_container=[]

    # Searching result container of category objects and menuitem objects
    categoriesObj=[]
    menuitemsObj=[]

    # Post to server
    if request.method=='POST':

        search_input=request.form['search_input']

        search_inputList=search_input.strip().split()

        for i in search_inputList:

            # List of categories that find in database
            for category in categoryName_List:
                category_List=category.strip().split()
                for j in category_List:
                    if count_mismatch(i, j)!=2 or single_fix(i, j)!=2:
                        categories_container.append(category)
                        categoriesObj.append(getCategoryInfo(getCategoryID(category)))

            # List of menuitems that find in database
            for menuitem in menuItem_List:
                menuitem_List=menuitem.strip().split()
                for j in menuitem_List:
                    if count_mismatch(i, j)!=2 or single_fix(i, j)!=2:
                        menuitems_container.append(menuitem)
                        menuitemsObj.append(getMenuitemInfo(getMenuitemID(menuitem)))

        # Get more categories from menu items
        for iname in menuitemsObj:
            ent=getMenuitemInfo(getMenuitemID(iname.name))
            if getCategoryInfo(ent.category_id) not in categoriesObj:
                categoriesObj.append(getCategoryInfo(ent.category_id))

    flash("Search-result('" + search_input + "')")

    return render_template('search_result.html',
                            email_user=email,
                            userID=userID,
                            username=username,
                            categoryName_List=categoryName_List,
                            cate_list=[],
                            item_list=[],
                            categories=categoriesObj,
                            items=menuitemsObj,
                            search_input=search_input)


# Delete an already menu_item off the database
@app.route('/catalog/<string:category_name>/<string:item_name>/delete',
            methods=['GET', 'POST'])
def deleteMenuItem(category_name, item_name):

    # searching input content
    global search_input

    if 'email' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(name=category_name).one()

    itemToDelete = session.query(MenuItem).filter_by(name=item_name, category_id=category.id).one()
    user = session.query(User).filter_by(email=login_session['email']).one()

    if itemToDelete.user_id != user.id and user.name != 'admin':
        flash("Can not delete this item")
        return redirect(url_for('seccategoryitemMenu',
                        category_name=category.name))

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Deleted item: %s" % itemToDelete.name)
        return redirect(url_for('seccategoryitemMenu',
                                category_name=category.name))
    else:
        return render_template('deletemenuitem.html',
                                category_name=category.name,
                                item_name=item_name,
                                email_user=login_session['email'],
                                search_input=search_input)


# Delete an already category off the database
@app.route('/catalog/<string:category_name>/delete',
            methods=['GET', 'POST'])
def deleteCategory(category_name):

    # searching input content
    global search_input

    # Verify the logged in status
    if 'email' not in login_session:
        return redirect('/login')

    # Retrieve the category going to delete
    categoryToDel = session.query(Category).filter_by(name=category_name).one()

    # Gets the list of items inside the specific category
    itemsList = ItemNamesinCategory(category_name)

    # Retrieve the logged in user
    user = session.query(User).filter_by(email=login_session['email']).one()

    # Verify who's the user logged in
    if categoryToDel.user_id != user.id and user.name != 'admin':
        flash('Can not delete this category')
        return redirect(url_for('seccategoryitemMenu',
                                category_name=category_name))

    # Category is not empty
    if len(itemsList) != 0:
        flash("%s is not empty" % category_name)
        return redirect(url_for('seccategoryitemMenu',
                                category_name=category_name))

    # If everythings okay, delete
    if (request.method=='POST') and (len(itemsList)==0):
        session.delete(categoryToDel)
        session.commit()
        flash("Deleted category: %s" % categoryToDel.name)

        return redirect(url_for('seccatalogMenu'))

    # Here is the confirm page to delete
    else:
        return render_template('deletecategory.html',
                                category_name=category_name,
                                email_user=login_session['email'],
                                search_input=search_input)


# Create a new menu_item
@app.route('/catalog/<string:category_name>/new',
            methods=['GET', 'POST'])
def newMenuItem(category_name):

    # searching input content
    global search_input

    # searching input content
    global search_input

    # Reset the Errors var
    Errors = {}

    # Verrify the logged in status
    if 'email' not in login_session:
        return redirect('/login')

    # Verify logged-in user in database,
    # creates new user for the first log in.
    login_UserID = getUserID(login_session['email'])
    if not login_UserID:
        login_UserID = createUser(login_session)
        login_session['user_id'] = login_UserID

    # Retrieve the category and user
    category=session.query(Category).filter_by(name=category_name).one()
    user=session.query(User).filter_by(email=login_session['email']).one()

    if request.method=='POST':

        # Validate name input
        Errors.update(valid_name(request.form['name']))

        # Validate price input
        Errors.update(valid_price(request.form['price']))

        # Validate description input
        Errors.update(valid_description(request.form['description']))

        # The name input is exist
        if request.form['name'] in ItemNamesinCategory(category.name):
            Errors['double']='Name is exist'

        # Verify image input
        image=request.form['image']

        # if everything okay, create new
        if Errors=={}:
            newItem = MenuItem(name=request.form['name'],
                               description=request.form['description'],
                               price=request.form['price'],
                               image=image,
                               kind=request.form['kind'],
                               user_id=login_UserID,
                               category_id=category.id)

            session.add(newItem)
            session.commit()
            flash("%s item created" % newItem.name)
            return redirect(url_for('seccategoryitemMenu',
                                    category_name=category_name))
        # vice versa reinputs the new item
        else:
            return render_template('newmenuitem.html',
                                    category_name=category_name,
                                    email_user=login_session['email'],
                                    Errors=Errors,
                                    search_input=search_input)
    # Here is the first page, filling some inputs
    else:
        return render_template('newmenuitem.html',
                                category_name=category_name,
                                email_user=login_session['email'],
                                Errors=Errors,
                                search_input=search_input)

# Create a new category

@app.route('/category/<string:category_name>/new',
            methods=['GET', 'POST'])
def newCategory(category_name):

    # searching input content
    global search_input

    # Reset the Errors var
    Errors = {}

    # Verify the loged in status
    if 'email' not in login_session:
        return redirect('/login')

    # Verify logged-in user in database,
    # creates new user for the first log in.
    login_UserID = getUserID(login_session['email'])
    if not login_UserID:
        login_UserID = createUser(login_session)
        login_session['user_id'] = login_UserID

    # The list of all categories
    categories_list = ListAllCategories()

    if request.method=='POST':

        # Validate the name input
        #if not valid_name(request.form['name']):
        #    Errors['name']='Invalid name'
        Errors.update(valid_name(request.form['name']))

        # The name input is exist
        if request.form['name'] in categories_list:
            Errors['double']='Name is exist'

        # If everythings okay, creates new category
        if Errors=={}:
            newCategory = Category(name=request.form['name'],
                                    user_id=login_UserID)
            session.add(newCategory)
            session.commit()
            flash("%s category created!" % newCategory.name)
            return redirect(url_for('seccategoryitemMenu',
                                    category_name=category_name,
                                    email_user=login_session['email']))

        # Vice versa reinput the category name
        else:
            return render_template('newcategory.html',
                                    category_name=category_name,
                                    email_user=login_session['email'],
                                    Errors=Errors,
                                    search_input=search_input)

    # Here is the first page to create new category
    else:
        return render_template('newcategory.html',
                                category_name=category_name,
                                email_user=login_session['email'],
                                Errors=Errors,
                                search_input=search_input)

# Login page
@app.route('/manual/login', methods=['GET', 'POST'])
def manual_login():

    # searching input content
    global search_input
    search_input=''

    # Reset category access list
    global category_access_list
    global item_access_list
    category_access_list = []
    item_access_list = []

    if request.method=='POST':

        # Retrieve all categories and items which has kind is 'new'
        categories = session.query(Category)
        items = session.query(MenuItem).filter_by(kind="new").all()

        name_inputed=request.form['manual_email']
        password=request.form['password']

        try:
            # Retrieve user who is logging in
            userID = getUserID(name_inputed)
            user = getUserInfo(userID)
            h = user.pw_hash

            # Build the login_session
            login_session['email'] = user.email
            login_session['password'] = password
            login_session['name'] = name_inputed
            login_session['username'] = name_inputed


            if valid_pw(name_inputed, password, h):
                flash("Logged in as %s" % login_session['name'])

                return render_template('sec_catalog.html',
                                        categories=categories,
                                        items=items,
                                        email_user=login_session['email'],
                                        cate_list=category_access_list,
                                        item_list=item_access_list,
                                        search_input=search_input)
            else:
                flash("Invalid password")
                return render_template('sec_catalog.html',
                                        categories=categories,
                                        items=items,
                                        search_input=search_input)
        except:
            flash('Sign Up first, please!')
            return render_template('sec_catalog.html',
                                    categories=categories,
                                    items=items,
                                    search_input=search_input)

    else:
        return render_template('login.html')


@app.route('/manual/signup', methods=['GET', 'POST'])
def signup():

    # searching input content
    global search_input
    search_input=''

    # Reset category access list
    global category_access_list
    global item_access_list
    category_access_list = []
    item_access_list = []

    # Reset the Errors var
    Errors = {}

    if request.method=='POST':
        email = request.form['manual_email']
        password = request.form['password']
        verify = request.form['verify']

        # -------------Validate input----------------
        # Validate the name input
        Errors.update(valid_name(email))

        # Validate the Password
        Errors.update(valid_password(password))


        if password==verify and Errors=={}:

            # User is already exist in database
            try:
                userID = getUserID(email)
                categories = session.query(Category)
                items = session.query(MenuItem).filter_by(kind="new").all()
                flash("Logged in as %s" % login_session['name'])
                return render_template('sec_catalog.html',
                                        categories=categories,
                                        items=items,
                                        email_user=login_session['email'],
                                        cate_list=category_access_list,
                                        item_list=item_access_list)


            # User isn't in database, add new
            except:
                # Build the login_session
                login_session['email'] = email
                login_session['name'] = email
                login_session['username'] = email
                login_session['picture'] = ""
                h = make_pw_hash(email, password)
                login_session['pw_hash'] = h

                # Save in database
                user_id = createUser(login_session)
                login_session['user_id'] = user_id

                # Retrieve from database
                categories = session.query(Category)
                items = session.query(MenuItem).filter_by(kind="new").all()
                flash("Logged in as %s" % login_session['name'])

                return render_template('sec_catalog.html',
                                        categories=categories,
                                        items=items,
                                        email_user=login_session['email'],
                                        cate_list=category_access_list,
                                        item_list=item_access_list)

        else:
            Errors['verify_password']="Password and Verify aren't similar"
            return render_template('signup.html',
                                    hideSignup=True,
                                    error_verify="Invalid password",
                                    email=email,
                                    Errors=Errors)

    else:
        return render_template('signup.html',
                                hideSignup=True,
                                Errors=Errors)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():

    # searching input content
    global search_input
    search_input=''

    # Reset the access list var
    global category_access_list
    global item_access_list
    category_access_list = []
    item_access_list = []

    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            clearSession()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        login_session.clear()
        flash("Logged out")
        return redirect(url_for('catalogMenu'))
    else:
        login_session.clear()
        flash("Logged out")
        return redirect(url_for('seccatalogMenu'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

