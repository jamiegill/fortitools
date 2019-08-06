from . import app
from flask import render_template, request, redirect, url_for, flash
@app.route("/")
def get_root():
     return render_template("main_page.html")




