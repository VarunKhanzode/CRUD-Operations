import json
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow import fields, Schema, ValidationError, validate
from flask_bcrypt import Bcrypt

from datetime import datetime, timedelta, timezone

from flask_jwt_extended import create_access_token, create_refresh_token
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request, decode_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:varun123@localhost/User_Register'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "ABC"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=1)

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    __tabelname__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String,nullable=False,unique=True)
    pass1 = db.Column(db.String,nullable=False)
    profile = db.relationship("Profile",backref="user", uselist=False)
    books = db.relationship("Books",backref="user")

    def __repr__(self):
        return self.name

class Profile(db.Model):
    __tablename__ = "profile"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True)
    email = db.Column(db.String,nullable=False,unique=True)
    age = db.Column(db.Integer,nullable=False)
    address = db.Column(db.String,nullable=False)
    gender = db.Column(db.String,nullable=False)

class Books(db.Model):
    __tablename__ = "books"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False,unique=True)
    authorName = db.Column(db.String, nullable=False)
    publishDate = db.Column(db.Integer, nullable=False)
    genre = db.Column(db.String, nullable=False)
    type = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self):
        return self.name
    
class User_Validation(Schema):
    name = fields.Str(required=True,max=50)
    pass1 = fields.Str(required=True,max=50)
    email = fields.Email(required=True,max=50)
    age = fields.Int(required=True,max=100)
    address = fields.Str(required=True,max=50)
    gender = fields.Str(required=True,max=50)

    class Meta:
        ordered = True

class Book_Validation(ma.Schema):
    name = fields.Str(required=True,max=50)
    authorName = fields.Str(required=True,max=50)
    publishDate = fields.Int(required=True,max=50)
    genre = fields.Str(required=True,max=50)
    type = fields.Str(required=True,max=50)

    class Meta:
        ordered = True
        
userValidation = User_Validation(exclude=['pass1'],many=True)
registerValidation = User_Validation()
loginValidation = User_Validation(only=('name','pass1'))
bookValidation = Book_Validation()
booksValidation = Book_Validation(many=True)
updateBookValidation = Book_Validation(exclude=['name'])

@app.route("/")
def Home():
    return "Home Page"

@app.route("/Register", methods=["POST"])
def Register():
    try:
        data = request.get_json()
        registerValidation.load(data)

        enc_pass1 = bcrypt.generate_password_hash(data['pass1']).decode('utf-8')

    except ValidationError as err:
        return err.messages

    except Exception as err:
        return str(err)

    user1 = User(name=data['name'], pass1=enc_pass1)
    db.session.add(user1)
    db.session.commit()

    profile1 = Profile(user=user1, email = data['email'], age=data['age'], address=data['address'], gender=data['gender'])
    db.session.add(profile1)
    db.session.commit()

    return 'Successfully Registered'

@app.route("/login", methods=["POST"])
def login():
    try:
        data =request.get_json()

    except ValidationError as err:
        return err.messages

    except Exception as err:
        return str(err) 
    
    result = User.query.filter_by(name=data['name']).first()    

    if result is None:
        return "incorrect username"

    elif (bcrypt.check_password_hash(result.pass1, data['pass1'])):
        additional_claims = {"User_ID": result.id}
        access_token = create_access_token(identity=result.id,additional_claims=additional_claims)
        refresh_token = create_refresh_token(identity=result.id)
        return jsonify(access_token=access_token, refresh_token=refresh_token)
    
    else:
        return jsonify({"Error" : "Incorrect Credentials"})

@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)
    
@app.route("/create", methods=["POST"])
def create():
    try:
        dToken = decode_token(request.headers.get('API'))
        data = request.get_json()
        bookValidation.load(data)

    except ValidationError as err:
        return err.messages

    except Exception as err:
        return str(err)
    
    identity = dToken['User_ID']

    b1 = Books(name=data['name'],authorName=data['authorName'],publishDate=data['publishDate'],genre=data['genre'],type=data['type'],user_id=identity)

    db.session.add(b1)
    db.session.commit()

    return jsonify({"Status" : "Success"})

@app.route("/read", methods=["GET"])
def read():
    try:
        dToken = decode_token(request.headers.get('API'))
        id = dToken['User_ID']

        result = Books.query.filter_by(user_id=id).all()

        if result is None:
            return "No books issued"

    except Exception as err:
        return str(err)

    data = booksValidation.dumps(result)
    return data

@app.route('/update/<string:oldBookName>', methods=['PATCH'])
def update(oldBookName):
    try:
        dToken = decode_token(request.headers.get('API'))
        id = dToken['User_ID']

        data = request.get_json()
        updateBookValidation.load(data)

    except Exception as err:
        return str(err)

    result = Books.query.filter_by(user_id=id).all()

    if result is None:
         return jsonify({"Error" : "No books issued"})

    for book in result:
        if (book.name == oldBookName):
            book.authorName = data['authorName']
            book.publishDate = data['publishDate']
            book.genre = data['genre']
            book.type = data['type']

            db.session.commit()
            return jsonify({"Status" : "Updated"})
            
    else:
        return jsonify({"Error" : "Book not found"})

@app.route('/delete/<string:bookName>',methods=['DELETE'])
def delete(bookName):
    try:
        dToken = decode_token(request.headers.get('API'))
        id = dToken['User_ID']

        result = Books.query.filter_by(user_id=id).all()
        if result is None:
            return jsonify({"Error" : "No books available"})

    except Exception as err:
        return str(err)

    for book in result:
        if (book.name==bookName):
            db.session.delete(book)
            db.session.commit()
            return jsonify({"Status" : "Deleted"})

    else:
        return jsonify({"Error" : "Book not found"})

@app.route('/retrieve',methods=['GET'])
def retrieve_all():
    Users = User.query.all()
    result = []
    for user in Users:
        data = userValidation.dump([user,user.profile])
        result.append(data)
    return result


if __name__ == "__main__":
    app.run(debug=True)


#u1 = User(uName='Rahul',pass1='123')
# p1 = Profile(user=u1,uEmail='rahul2EMAIL.COM',uAge=20,uAddress=202,userGender='male')

# {
#     "name" : "aman",
#     "pass1" : "123",
#     "email" : "aman@email.com",
#     "age" : 20,
#     "address" : "bengaluru"
# }

# {
#     "name" : "Python",
#     "authorName" : "Michalle",
#     "publishDate" : 2019,
#     "genre" : "Educational",
#     "type" : "Non-Fictional"
# }

# {
#     "name" : "XYZ",
#     "pass1" : "1453"
# }

# {
#     "name" : "Yashwant",
#     "pass1" : "123",
#     "email" : "yash@email.com",
#     "age" : 26,
#     "address" : "Bengaluru",
#     "gender" : "Male"
# }
