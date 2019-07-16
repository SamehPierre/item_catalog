#!/usr/bin/env python3
import os
from flask import Flask, render_template, request, redirect, jsonify, \
    url_for, flash, send_from_directory
from werkzeug.utils import secure_filename

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Brand, Model, User

from flask import session as login_session
import random
import string

# from oauth2client import client
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import logging

UPLOAD_FOLDER = 'static'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///ComputerShop.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)


# Create a state token to prevent request
# Store it in the session for later
@app.route('/login')
def show_login():
    """ Create state token and store it in session."""

    state = ''.join(random.choice(string.ascii_uppercase + string.
                                  digits) for x in range(32))
    login_session['state'] = state
    # Render the login template
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Connect with google."""
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
        response = make_response(json.dumps(
            result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps(
                "Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        logging.info("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    # login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = get_user_id(data["email"])
    if user_id is None:
        user_id = create_user(login_session)
    login_session['userid'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '"style = "width: 300px; height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("you are now logged in as %s" % login_session['username'])
    logging.info("done!")
    return output


# User Helper Functions

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    """Disconnect from google."""
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps(
            'Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    """Delete stored session."""
    del login_session['access_token']
    del login_session['username']
    del login_session['userid']
    del login_session['picture']
    del login_session['email']
    del login_session['gplus_id']
    del login_session['state']

    flash("You have successfully been logged out.")
    return redirect(url_for('show_brands'))


# User Helper Functions
def create_user(login_session):
    """create new user and return user id."""
    session = DBSession()
    new_user = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one_or_none()
    return user.id


def get_user_info(user_id):
    """Return user information"""

    session = DBSession()
    user = session.query(User).filter_by(id=user_id).one_or_none()
    return user


def get_user_id(email):
    """Return user id."""

    session = DBSession()
    user = session.query(User).filter_by(email=email).one_or_none()
    if user is None:
        return None
    return user.id


# JSON APIs to view Brand Information
@app.route('/brand/<int:brand_id>/model/JSON')
def brand_json(brand_id):
    """Returns Laptop Models in a JSON Format"""
    session = DBSession()
    # brand = session.query(Brand).filter_by(id = brand_id).one()
    models = session.query(Model).filter_by(brand_id=brand_id).all()
    return jsonify(Models=[i.serialize for i in models])


@app.route('/brand/<int:brand_id>/model/<int:model_id>/JSON')
def model_json(brand_id, model_id):
    """Returns Laptop Model in a JSON Format"""

    session = DBSession()
    model = session.query(Model).filter_by(id=model_id).one()
    return jsonify(Model=model.serialize)


@app.route('/brand/JSON')
def brands_json():
    session = DBSession()
    brands = session.query(Brand).all()
    return jsonify(brands=[r.serialize for r in brands])


# Show all brands
@app.route('/')
@app.route('/brand/')
def show_brands():
    """Render brands.Html with permission (edit, delete)."""
    session = DBSession()
    brands = session.query(Brand).order_by(asc(Brand.name))

    if 'username' not in login_session:
        return render_template('brands.html', brands=brands,
                               is_admin=False)
    else:
        return render_template('brands.html', brands=brands,
                               is_admin=True)


@app.route('/static/<path:filename>')
def send_file(filename):
    """Return photo path."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Create a new brand
@app.route('/brand/new/', methods=['GET', 'POST'])
def new_brand():
    """Add new Laptop brand."""
    try:
        session = DBSession()
        if request.method == 'POST':
            name = request.form['name']
            if name != '':
                file = request.files['photo']
                # if user does not select file, browser also
                # submit a empty part without filename
                # if file.filename == '':
                # flash('No selected file')
                # return redirect(request.url)
                if file and allowed_file(file.filename):
                    filename = secure_filename(name +
                                               file.filename).replace(" ", "")
                    photo = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(photo)
                else:
                    flash('File Extention is not allowed')
                newbrand = Brand(name=request.form['name'], photo=filename,
                                 user_id=login_session['userid'])
                session.add(newbrand)
                session.commit()
                flash('New Brand %s Successfully Created' % newbrand.name)
            return redirect(url_for('show_brands'))
        else:
            return render_template('brandNew.html')
    except Exception as ex:
        return logging.error(str(ex))


# Edit brand
@app.route('/brand/<int:brand_id>/edit/', methods=['GET', 'POST'])
def edit_brand(brand_id):
    """Edit brand if the created user is the same as the editing user."""
    session = DBSession()
    edited_brand = session.query(Brand).filter_by(id=brand_id).one()
    if request.method == 'POST':
        created_user = edited_brand.user_id
        logged_user = login_session['userid']
        if created_user != logged_user:
            flash('You are not authorized to edit')
            return redirect(url_for('show_brands'))

        edit_btn = request.form.get('edit')
        if edit_btn is not None:
            if request.form['name']:
                edited_brand.name = request.form['name']
                edited_brand.user_id = login_session['userid']
                session.commit()
                flash('Brand Successfully Edited %s' % edited_brand.name)
        return redirect(url_for('show_brands'))
    else:
        return render_template('brandEdit.html', brand=edited_brand)


# Delete brand and its models
@app.route('/brand/<int:brand_id>/delete/', methods=['GET', 'POST'])
def delete_brand(brand_id):
    """Delete brand if the created user is the same as the deleting user."""
    session = DBSession()
    deleted_brand = session.query(Brand).filter_by(id=brand_id).one()
    if request.method == 'POST':
        delete_btn = request.form.get('delete')
        creadted_user = deleted_brand.user_id
        logged_user = login_session['userid']
        if creadted_user != logged_user:
            flash('You are not authorized to delete')
            return redirect(url_for('show_brands', brand_id=brand_id))
        if delete_btn is not None:
            delete_btn = request.form.get('delete')
            if delete_btn is not None:
                session.delete(deleted_brand)
                flash('%s Successfully Deleted' % deleted_brand.name)
                session.commit()
        return redirect(url_for('show_brands', brand_id=brand_id))

    else:
        return render_template('brandDelete.html', brand=deleted_brand)


# Show a brand model
@app.route('/brand/<int:brand_id>/')
@app.route('/brand/<int:brand_id>/model/')
def show_model(brand_id):
    """Render model.Html with user permission (edit, delete)."""
    session = DBSession()
    brand = session.query(Brand).filter_by(id=brand_id).one()
    models = session.query(Model).filter_by(brand_id=brand_id).all()

    user = get_user_info(brand.user_id)

    if 'userid' in login_session:
        userid_session = login_session['userid']
        if not user or 'username' not in login_session or \
                brand.user_id != userid_session:
            return render_template('model.html', models=models, brand=brand,
                                   creator=user, is_admin=False)
        else:
            return render_template('model.html', models=models, brand=brand,
                                   creator=user, is_admin=True)
    else:
        return render_template('model.html', models=models, brand=brand,
                               creator=user, is_admin=False)


# Create a new brand model
@app.route('/brand/<int:brand_id>/model/new/', methods=['GET', 'POST'])
def new_model(brand_id):
    """Add new laptop model."""
    session = DBSession()
    # brand = session.query(Brand).filter_by(id = brand_id).one()
    if request.method == 'POST':
        file = request.files['photo']
        # if user does not select file, browser also
        # submit a empty part without filename
        # if file.filename == '':
        # flash('No selected file')
        # return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(request.form['name'] +
                                       file.filename).replace(" ", "")
            photo = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(photo)

            newmodel = Model(name=request.form['name'],
                             description=request.form['description'],
                             price=request.form['price'],
                             photo=filename, brand_id=brand_id)
            session.add(newmodel)
            session.commit()
            flash('New Labtop Model %s Item Successfully Created' %
                  newmodel.name)
            return redirect(url_for('show_model', brand_id=brand_id))
        else:
            flash('Brand must have a logo')
            return render_template('modelNew.html', brand_id=brand_id)
    else:
        return render_template('modelNew.html', brand_id=brand_id)


# helper for allowed photos ext.
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Edit a brand model
@app.route('/brand/<int:brand_id>/model/<int:model_id>/edit',
           methods=['GET', 'POST'])
def edit_model(brand_id, model_id):
    """Modify laptop model only

    if the created user is the same as the editing user.
    """
    session = DBSession()
    edited_model = session.query(Model).filter_by(id=model_id).one()
    if request.method == 'POST':
        edit_btn = request.form.get('edit')
        creadted_user = edited_model.user_id
        logged_user = login_session['userid']
        if creadted_user != logged_user:
            flash('You are not authorized to edit')
            return redirect(url_for('show_model', brand_id=brand_id))
        if edit_btn is not None:
            if request.form['name']:
                edited_model.name = request.form['name']
            if request.form['description']:
                edited_model.description = request.form['description']
            if request.form['price']:
                edited_model.price = request.form['price']
            edit_model.user_id = login_session['userid']
        # if 'photo' not in request.files:
        # flash('No file part')
        # return redirect(request.url)
            file = request.files['photo']
        # if user does not select file, browser also
        # submit a empty part without filename
        # if file.filename == '':
        # flash('No selected file')
        # return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(request.form['name'] +
                                           file.filename).replace(" ", "")
                photo = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(photo)
                edited_model.photo = filename
            session.add(edited_model)
            session.commit()
            flash('Menu Item Successfully Edited')
        return redirect(url_for('show_model', brand_id=brand_id))
    else:
        return render_template('modelEdit.html', brand_id=brand_id,
                               model_id=model_id, model=edited_model)


# Delete brand Model
@app.route('/brand/<int:brand_id>/model/<int:model_id>/delete',
           methods=['GET', 'POST'])
def delete_model(brand_id, model_id):
    """Remove model"""
    session = DBSession()
    deleted_model = session.query(Model).filter_by(id=model_id).one()

    if request.method == 'POST':
        delete_btn = request.form.get('delete')
        edit_btn = request.form.get('edit')
        creadted_user = deleted_model.user_id
        logged_user = login_session['userid']
        if creadted_user != logged_user:
            flash('You are not authorized to delete')
            return redirect(url_for('show_model', brand_id=brand_id))
        if delete_btn is not None:
            session.delete(deleted_model)
            session.commit()
            flash('Menu Item Successfully Deleted')
            return redirect(url_for('show_model', brand_id=brand_id))
        else:
            return redirect(url_for('show_model', brand_id=brand_id))
    else:
        return render_template('modelDelete.html', model=deleted_model)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
