from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from .forms import CreateUserForm
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.http import HttpResponse
#import messages
from django.contrib import messages
from django.contrib.auth.decorators import login_required

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