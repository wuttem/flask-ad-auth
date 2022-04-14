# In you App Init
from flask import Flask
from flask import url_for, redirect, request
from flask_ad_auth import ADAuth

app = Flask(__name__)
app.secret_key = <SOME SECRET KEY>
app.config.update(
    AD_SQLITE_DB = "my_user_db.db3",
    AD_APP_ID = <YOUR APP ID>,
    AD_APP_KEY = <YOUR APP KEY>,
    AD_REDIRECT_URI = "http://localhost:5000/connect/get_token",
    AD_LOGIN_REDIRECT = "/login_form"
)
ad_auth = ADAuth()
ad_auth.init_app(app)

# In you Views:
from flask_ad_auth import login_required, current_user, ad_group_required, logout_user

# optional automatic redirect to login form:
def redirect_unauthorized():
    login_form_url = url_for("login_form")
    # we need to make sure that we dont redirect on login requests
    if login_form_url not in request.url and "/get_token" not in request.url:
        if not current_user or not current_user.is_authenticated:
            return redirect(login_form_url)
app.before_request(redirect_unauthorized)

@app.route('/protected')
@login_required
def protected_view():
    return "Logged in as {}".format(current_user.email)

@app.route('/group_protected')
@ad_group_required("sdadsad-6a93-d3432-a4be-f1cbsdsaa0d4")
def group_protected_view():
    return "Logged in as {}".format(current_user.email)

@app.route('/logout')
def logout():
    logout_user()
    return 'Logged out<br/><a href="{}">goto login page</a>'.format(url_for("login_form"))

@app.route('/login_form')
def login_form():
    if current_user.is_authenticated:
        return 'logged in<br/><a href="{}">logout</a>'.format(url_for("logout"))
    return 'not logged in<br/><a href="{}">login</a>'.format(ad_auth.sign_in_url)

if __name__ == '__main__':
	app.run( debug=True, host='0.0.0.0', port=5000)