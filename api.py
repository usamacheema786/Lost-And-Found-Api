from flask import Flask ,request,jsonify,make_response 
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash,generate_password_hash
import jwt
from jwt import *
import datetime
from functools import wraps
import json
import re
# from app import models


app=Flask(__name__)

app.config['SECRET_KEY'] ='secret key'
app.config['SQLALCHEMY_DATABASE_URI']='mysql://root:@localhost/found_lost'
db =SQLAlchemy(app)

# Databse Models
class users(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(255))
    password=db.Column(db.String(255))
    # item=db.relationship('items',backref='users',lazy='dynamic')

class items(db.Model):
    
    id = db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(255))
    description=db.Column(db.String(10000))
    category=db.Column(db.String(255))
    location=db.Column(db.String(255))
    date=db.Column(db.String(255))
    user_id=db.Column(db.Integer)
#-------------------------------------------------------------------------------------
# decorator overwrite
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token =None
        if 'access-token' in request.headers:
            token = request.headers['access-token']
        if not token:
            return jsonify({'message':'Token is miising'})
        try:
            data =jwt.decode(token,app.config['SECRET_KEY'])
            current_user = users.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message':'Invalid token'}),401

        return f(current_user,*args,**kwargs)
    return decorated

#decorator for registration 
@app.route('/signup',methods=['POST'])
def signup():
    data =request.get_json()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
        return jsonify({'message':'provide correct email '})
    user = users.query.filter_by(email=data['email']).first()
    if not user:
        hash_password = generate_password_hash(data['password'])
        new_user =users(email=data['email'],password=hash_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message':'new user is added'})
    return jsonify({'message':'Email already registered'})


#decorator for change password
@app.route('/changePassword',methods=['PUT'])
@token_required
def changePassword(current_user):
    if not current_user:
        return jsonify({'message':'please login first to perform this operation'})
    data=request.get_json()
    if data['password'] !='':
        hashed_pass=generate_password_hash(data['password'])
        current_user.password=hashed_pass
        db.session.commit()
        return jsonify({'message':'password changed successfully'})
    return jsonify({'message':'password field is required'})

@app.route('/addPost',methods=['POST'])
@token_required
def add_Post(current_user):
    if not current_user:
        return jsonify({'message':'please login first to perform this operation'})
    data = request.get_json()
    new_item = items(name=data['name'],description=data['description'],category=data['category'],location=data['location'],date=data['date'])
    new_item.user_id=current_user.id
    db.session.add(new_item)
    db.session.commit()
    return jsonify({'message': 'New item added'})


@app.route('/allPosts',methods=['GET'])
@token_required
def viewAllPosts(current_user):
    if not current_user:
        return jsonify({'message':'please login first to perform this operation'})
    Items =items.query.all()
    if not Items:
        return jsonify({'message':'No item exist'})
    data =[]
    for item in Items:
        item_data={}
        item_data['name']=item.name
        item_data['description'] =item.description
        item_data['category']=item.category
        item_data['location']=item.location
        item_data['date']=item.date
        data.append(item_data)
    return jsonify({'All Item':data})

@app.route('/deletePost/<item_id>',methods=['DELETE'])
@token_required
def deletePost(current_user,item_id):
    if not current_user:
        return jsonify({'message':'login first'})
    item =items.query.filter_by(id=item_id).first()
    if not item:
        return jsonify({'message':'item not found'})
    else:
        if item.user_id==current_user.id:
            db.session.delete(item)
            db.session.commit()
            return jsonify({'message':'item successfully deleted'})
        else:
            return jsonify({'message':'you cannot perform this operation'})


@app.route('/searchPost/<name>',methods=['GET'])
@token_required
def searchPost(current_user,name):

    item =items.query.filter_by(name=name).first()
    if not item:
        return jsonify({'message':'item not found'})
    item_data={}
    item_data['name']=item.name
    item_data['description'] =item.description
    item_data['category']=item.category
    item_data['location']=item.location
    item_data['date']=item.date
    return jsonify({'item':item_data})

@app.route('/updatePost/<id>',methods=['PUT'])
@token_required
def updatePost(current_user,id):
    if not current_user:
        return jsonify({'message':'Login first'})
    data=request.get_json()   
    item =items.query.filter_by(id=id).first()
    if not item:
        return jsonify({'message':'Item does not exist'})
    else:
        if item.user_id==current_user.id:   
            if 'name' in data:
                item.name = data['name']
            if 'description' in data:
                item.description=data['description']
            if 'date' in data:
                item.date=data['date']
            if 'location' in data:
                item.location=data['location']
            if 'category' in data:
                item.category=data['category']
            db.session.commit()    
            return jsonify({'message':'Post is updated'})
        else:
            return jsonify({'message':'you cannot update this Post'})
    return jsonify({'message':'Post is not updated ,try again later'})

    


@app.route('/login')
def login():
    auth_data=request.authorization

    if not auth_data or not auth_data.username or not auth_data.password:
        return make_response('incorect login detail1',401,{'WWW-Authenticate':'Basic realm="Login required"'})
    user =users.query.filter_by(email=auth_data.username).first()
    if not user:
        return make_response('incorect login detail2',401,{'WWW-Authenticate':'Basic realm="Login required"'})
     
    if check_password_hash(user.password,auth_data.password):
        token =jwt.encode({'id':user.id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=10)},app.config['SECRET_KEY'])
        return jsonify({'token':token.decode('UTF-8')})
    return make_response('incorect login detail3',401,{'WWW-Authenticate':'Basic realm="Login required"'})


if __name__ == "__main__":
    app.run(debug=True)