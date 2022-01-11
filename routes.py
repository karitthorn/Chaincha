from flask import (
    Flask,
    render_template,
    redirect,
    flash,
    url_for,
    session
)

from datetime import timedelta
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError,
)
from werkzeug.routing import BuildError


from flask_bcrypt import Bcrypt,generate_password_hash, check_password_hash

from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)

from app import create_app,db,login_manager,bcrypt
from models import User
from forms import login_form,register_form


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app = create_app()

@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)

@app.route("/", methods=("GET", "POST"), strict_slashes=False)
def index():
    return render_template("index.html",title="Home")


@app.route("/login/", methods=("GET", "POST"), strict_slashes=False)
def login():
    form = login_form()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if check_password_hash(user.pwd, form.pwd.data):
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash("Invalid Username or password!", "danger")
        except Exception as e:
            flash(e, "danger")

    return render_template("auth.html",
        form=form,
        text="Login",
        title="Login",
        btn_action="Login"
        )



# Register route
@app.route("/register/", methods=("GET", "POST"), strict_slashes=False)
def register():
    form = register_form()
    if form.validate_on_submit():
        try:
            email = form.email.data
            pwd = form.pwd.data
            username = form.username.data
            
            newuser = User(
                username=username,
                email=email,
                pwd=bcrypt.generate_password_hash(pwd),
            )
    
            db.session.add(newuser)
            db.session.commit()
            flash(f"Account Succesfully created", "success")
            return redirect(url_for("login"))

        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong!", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"User already exists!.", "warning")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry", "warning")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except DatabaseError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured !", "danger")
    return render_template("auth.html",
        form=form,
        text="Create account",
        title="Register",
        btn_action="Register account"
        )

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

###################################################################################
import datetime
import json
import hashlib
from flask import Flask, jsonify,render_template,request,session,flash
from flask_wtf import FlaskForm
from wtforms import SubmitField,StringField,BooleanField,RadioField,TextAreaField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_required

class MyForm(FlaskForm):
    name = StringField(" Blockchain Name",validators = [DataRequired()]) #ต้องกรอก
    datablock = TextAreaField("Data in this blockchain")
    isAccept = BooleanField("your acceptance of this policy*.",validators = [DataRequired()])
    submit = SubmitField("submit")

class cryptoform(FlaskForm):
    name = StringField(" crypto name",validators = [DataRequired()]) #ต้องกรอก
    symbol = StringField(" crypto symbol",validators = [DataRequired()])
    totalsupply = StringField("total supply",validators = [DataRequired()]) #ต้องกรอก
    decimals = StringField("decimals",validators = [DataRequired()])
    isAccept = BooleanField("your acceptance of this policy*.",validators = [DataRequired()])
    submit = SubmitField("submit")
    


#panpan
class Blockchain:
    def __init__(self,datablockchains):
        self.chain = [] #list ที่เก็บ block
        self.transactions =  "" #Data in blockchain
        #genesis block
        self.create_block(nonce=1,previos_hash="0",datablockchains = datablockchains)


    #สร้าง block ขึ้นมาใน blockchain
    def create_block(self,nonce,previos_hash,datablockchains):
        # เก็บส่วนประกอบของ Block เเต่ละ Block
        block ={
            "index":len(self.chain)+1,
            "timestamp":str(datetime.datetime.now()),
            "nonce" :nonce,
            "data": datablockchains,
            "previos_hash" :previos_hash
        }
        self.chain.append(block)
        return block

    #ให้บริการเกี่ยวกับ Block ก่อนหน้า
    def get_previos_block(self):
        return self.chain[-1]

    #เข้ารหัส block
    def hash(self,block):
        #เเปลง python object (dict) = > json object
        encode_block = json.dumps(block,sort_keys=True).encode()
        #sha-256
        return hashlib.sha256(encode_block).hexdigest()

    def proof_of_work(self,previos_nonce):
        #อยากได้ค่า nonce ที่ส่งผมให้ได target hash => 4 หลัก เป็น 0000xxxxxxxxxx
        new_nonce=1 #ค่า nonce ที่ต้องการ
        check_proof = False #ตัวเเปรที่เช็คค่า nonce ให้ได้ target ที่กำหนด

        #เเก้่โจทย์คณิตสาสตร์
        while check_proof is False:
            hashoperation = hashlib.sha256(str(new_nonce**2 - previos_nonce**2).encode()).hexdigest()
            if hashoperation[:4] == "0000":
                check_proof = True
            else:
                new_nonce+=1
        return new_nonce 
    def is_chain_valid(self,chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block["previos_hash"] != self.hash(previous_block):
                return False
            previos_nonce = previous_block["nonce"] #nonce ของ block ก่อนหน้า
            nonce = block["nonce"] #nonce  ของ block ที่กำลังตรวจสอบ
            hashoperation = hashlib.sha256(str(nonce**2 - previos_nonce**2).encode()).hexdigest()
            if hashoperation[:4] != "0000":
                return False
            previous_block=block
            block_index += 1
        return True


#web server 

#ใช้งาน blockchain 
datablockchains = ""
blockchain = Blockchain(datablockchains)

#routing
@app.route("/", methods=("GET", "POST"), strict_slashes=False)
def helloindex():
    return render_template("index.html",title="Home")

@app.route('/get_chain')
def get_chain():
    response ={
        "chain":blockchain.chain,
        "length":len(blockchain.chain),
    }
    return jsonify(response),200

@app.route('/mining',methods=['GET'])
def mining_block(datablockchains):
    blockchain.transactions = blockchain.transactions
    #pow
    previos_block = blockchain.get_previos_block()
    previos_nonce = previos_block["nonce"]
    #nonce
    nonce = blockchain.proof_of_work(previos_nonce)
    #hash block
    previos_hash = blockchain.hash(previos_block)
    #update block ใหม่
    block = blockchain.create_block(nonce,previos_hash,datablockchains)
    response ={
        "message":"Mining Block เรียบร้อย",
        "index":block["index"],
        "timestamp":block["timestamp"],
        "data":block["data"],
        "nonce" :block["nonce"],
        "previos_hash" :block["previos_hash"],

    }
    return jsonify(response),200

@app.route('/is_valid',methods=['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {"message":"Blockchain is Valid (Safe)"}
    else:
        response = {"message":"Have Problem, blockchain is not valid (Danger)"}

    return jsonify(response),200

#------------------------------------------------------------------------------------------------
Bootstrap(app)
app.config['SECRET_KEY'] = 'mykey' #สร้าง key

@app.route('/policy')
def policy():
    return render_template("policy.html")

@app.route('/createcryptocurrency', methods=['GET','POST'])
@login_required
def createcryptocurrency():
    
    name = False
    symbol = False
    totalsupply = False
    decimals = False
    isAccept = False
    submit = False
    form = cryptoform()
    if form.validate_on_submit():
        flash("Crypto code have been generator ") 
        
        session['name'] =  form.name.data
        session['symbol'] =  form.symbol.data
        session['totalsupply'] = form.totalsupply.data
        session['decimals'] = form.decimals.data
        session['isAccept'] = form.isAccept.data
        
        isAccept = form.isAccept.data
        name = form.name.data
        symbol = form.symbol.data
        totalsupply = form.totalsupply.data
        decimals = form.decimals.data

        form.isAccept.data = ""
        form.name.data = ""
        form.symbol.data = ""
        form.totalsupply.data = ""
        form.decimals.data = ""
        
    return render_template("createcryptocurrency.html",form=form,isAccept = isAccept,decimals = decimals,name = name,symbol = symbol,totalsupply = totalsupply)

@app.route('/create')
@login_required
def create():
    return render_template("create.html")#ให้ไปเเสดงผลที่ create.html

@app.route('/policycrypto')
def policycrypto():
    return render_template("policycrypto.html")
#panpan
@app.route('/createblockchain',methods=['GET','POST'])
@login_required
def createblockchain():
    global datablockchains

    name = False
    isAccept = False
    datablock = False
    form = MyForm()
    if form.validate_on_submit():
        flash("Blockchain have been created") 
        
        session['name'] =  form.name.data
        session['isAccept'] =  form.isAccept.data
        session['datablock'] = form.datablock.data
        

        name = str(form.name.data)
        isAccept = form.isAccept.data
        datablockchains =" name : " + str(form.name.data) + "  |  " + str(form.datablock.data)

        mining_block(datablockchains) # create new blockchain

        form.name.data = ""
        form.isAccept.data = ""
        
            
        
    return render_template("createblockchain.html",form = form,name = name,isAccept = isAccept)





@app.route('/sendData')
def signupForm():
    Blockchainname=request.args.get('Blockchainname')
    return render_template("MyBlockchain.html",Blockchainname = Blockchainname)
#------------------------------------------------------------------------------------------------
# login

########################################################################
#run server
if __name__ == '__main__':
    app.run(debug=False)
