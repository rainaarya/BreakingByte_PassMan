from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from .forms import CreateUserForm
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User, auth
from django.http import HttpResponse
#import messages
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Password_Details
from .encryption import encrypt, decrypt
from django.conf import settings

import random
import string

def generate_password(length, uppercase, lowercase, special_chars, numbers):
    characters = ''
    if uppercase:
        characters += string.ascii_uppercase
    if lowercase:
        characters += string.ascii_lowercase
    if special_chars:
        characters += string.punctuation
    if numbers:
        characters += string.digits
    
    if length > 45:
        return "Length must be between 4 and 45 characters."
    elif length < 4:
        return "Length must be between 4 and 45 characters."

    if characters == '':
        print('Error: No characters selected for password generation.')
        return "Error: No characters selected for password generation."
    else:
        password = ''.join(random.choice(characters) for i in range(length))
        return password


# Create your views here.

def home(request):
    if request.user.is_authenticated:
        return HttpResponse("You are logged in!")
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return HttpResponse("You are logged in!")
        else:
            messages.info(request, 'Username OR password is incorrect')

    return render(request, 'main/sign-in.html')

def sign_up(request):

    form = CreateUserForm()

    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponse("Account created successfully!")
        else:
            return render(request, 'main/sign-up.html', {'form': form})
        
    context = {'form': form}
    return render(request, 'main/sign-up.html', context)

@login_required(login_url='sign-in')
def sign_out(request):
    logout(request)
    return redirect('home')

@login_required(login_url='sign-in')
def generate(request):
    if request.method == 'POST':
        length = request.POST.get('length')
        uppercase = request.POST.get('uppercase')
        lowercase = request.POST.get('lowercase')
        numbers = request.POST.get('numbers')
        special_chars = request.POST.get('symbols')
        password = generate_password(int(length), uppercase, lowercase, special_chars, numbers)    
        return render(request, 'main/generate.html', {'password': password, 'length': length, 'uppercase': uppercase, 'lowercase': lowercase, 'numbers': numbers, 'special_chars': special_chars})

    return render(request, 'main/generate.html')

@login_required(login_url='sign-in')
def my_passwords(request):

    if request.user.is_authenticated:
        if request.method == 'POST':
            if request.POST.get('delete'):
                password_id = request.POST.get('delete')
                Password_Details.objects.filter(id=password_id).delete()
                return redirect('my-passwords')
            if request.POST.get('view-password'):
                request.session['id_pass'] = request.POST.get('view-password')
                return redirect('view-edit-password')
            if request.POST.get('search'):
                search = request.POST.get('search')
                passwords = Password_Details.objects.filter(user=request.user, website_name__icontains=search)
                if passwords:
                    for password in passwords:
                        password.website_name = password.website_name.capitalize()
                        password.website_notes = password.website_notes.capitalize()
                        password.website_password=''
                        password.website_link = "https://www.google.com/s2/favicons?sz=128&domain_url=" + password.website_link

                    return render(request, 'main/my-passwords.html', {'passwords': passwords})
                else:
                    return render(request, 'main/my-passwords.html')

        try:
            passwords = Password_Details.objects.filter(user=request.user)
        except Password_Details.DoesNotExist:
            return HttpResponse("You have no passwords saved yet!")
        
        #if passwords is not empty
        if passwords:
           
            for password in passwords:
                #capitalize the first letter of the website name
                password.website_name = password.website_name.capitalize()
                password.website_notes = password.website_notes.capitalize()
                password.website_password=''
                password.website_link = "https://www.google.com/s2/favicons?sz=128&domain_url=" + password.website_link

            return render(request, 'main/my-passwords.html', {'passwords': passwords})
        else:
            return render(request, 'main/my-passwords.html')
    else:
        return redirect('sign-in')


@login_required(login_url='sign-in')
def add_password(request):

    if request.user.is_authenticated:

        if request.method == 'POST':
            website_name = request.POST.get('website-name')
            website_link = request.POST.get('website-link')
            website_username = request.POST.get('website-username')
            website_password = request.POST.get('website-password')
            website_notes = request.POST.get('website-notes')

            website_password = encrypt(settings.SECRET_HERE.encode(), website_password.encode())    
            website_password = encrypt(settings.SECRET_HERE.encode(), website_password.encode())
            user = User.objects.get(username=request.user)
            password = Password_Details(user=user, website_name=website_name, website_link=website_link, website_username=website_username, website_password=website_password, website_notes=website_notes)
            password.save()
            return HttpResponse("Password added successfully!")


        return render(request, 'main/add-password.html')
    else:
        return redirect('sign-in')
    
@login_required(login_url='sign-in')
def view_edit_password(request):

    if request.user.is_authenticated:
        #if request session contains id_pass
        id_pass = None

        if 'id_pass' in request.session:
            id_pass=request.session['id_pass']
            #pop the id_pass from the session
            request.session.pop('id_pass')
            password_details = Password_Details.objects.get(id=id_pass)
            if request.user != password_details.user:
                return redirect('my-passwords')
            password_details.website_name = password_details.website_name.capitalize()
            password_details.website_notes = password_details.website_notes.capitalize()
            password_details.website_password = decrypt(settings.SECRET_HERE.encode(), password_details.website_password)
            password_details.website_password = decrypt(settings.SECRET_HERE.encode(), password_details.website_password)   

            
            return render(request, 'main/view-edit-password.html', {'password': password_details})
        else:
            return redirect('my-passwords')