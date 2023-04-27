from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from .forms import CreateUserForm
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User, auth
from django.http import HttpResponse
#import messages
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Password_Details, Profile
from .encryption import encrypt, decrypt
from django.conf import settings
from io import BytesIO
import base64
from django.core.mail import send_mail
from datetime import datetime, timedelta
import validators
import random
import string
# import URLField
from django.db import models
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError


import pyotp
import qrcode

def generate_secret_key():
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.secret

def verify_totp(secret_key, token):
    totp = pyotp.TOTP(secret_key)
    return totp.verify(token)

def calculate_level(xp):
    """
    Calculate the current level and XP percentage based on XP using a cumulative sum of preceding XP values
    """
    # XP values required to reach each level, using a cumulative sum of preceding XP values
    level_xp = [15, 35, 60, 90, 125, 165, 210, 260, 320, 390, 470, 560, 660, 770, 890, 1020, 1160, 1310, 1470, 1640, 1820]

    # Iterate over the level XP values to find the current level
    level = 0
    for xp_required in level_xp:
        if xp >= xp_required:
            level += 1
        else:
            break

    # Calculate XP percentage corresponding to the level
    if level == len(level_xp):
        xp_percentage = 100
    else:
        if level == 0:
            xp_required_for_current_level = 0
        else:
            xp_required_for_current_level = level_xp[level - 1]
        xp_required_for_next_level = level_xp[level]
        xp_difference = xp_required_for_next_level - xp_required_for_current_level
        xp_percentage = int(((xp - xp_required_for_current_level) / xp_difference) * 100)

    return level, xp_percentage

def give_password_strength_xp(password):
    """
    Create a password and return XP based on its strength category
    """
    # Determine the strength category based on password length and complexity

    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    numbers = string.digits
    symbols = string.punctuation

    upYes = False
    lowYes = False
    numYes = False
    symYes = False
    count = 0

    # Category 1: Weak (1XP)
    if len(password) < 8:
        xp = 1
    
    # Category 2: Medium (5XP)
    if len(password) >= 8 and len(password) <= 16:

        # Check if password contains uppercase letters
        if any(char in upper for char in password):
            upYes = True
            count += 1

        # Check if password contains lowercase letters
        if any(char in lower for char in password):
            lowYes = True
            count += 1

        # Check if password contains numbers
        if any(char in numbers for char in password):
            numYes = True
            count += 1

        # Check if password contains symbols
        if any(char in symbols for char in password):
            symYes = True
            count += 1

        if count >= 3:
            xp = 5
        else:
            xp = 1

    # Category 3: Strong (10XP)
    if len(password) > 16:
            
            # Check if password contains uppercase letters
            if any(char in upper for char in password):
                upYes = True
                count += 1
    
            # Check if password contains lowercase letters
            if any(char in lower for char in password):
                lowYes = True
                count += 1
    
            # Check if password contains numbers
            if any(char in numbers for char in password):
                numYes = True
                count += 1
    
            # Check if password contains symbols
            if any(char in symbols for char in password):
                symYes = True
                count += 1
    
            if count == 4:
                xp = 10
            elif count == 3:
                xp = 5
            else:
                xp = 1

    return xp



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

def generate_otp(secret_key):
    totp = pyotp.TOTP(secret_key)
    return totp.now()


# Create your views here.

def homepage(request):
    return render(request, 'main/homepage.html')

def home(request):
    if request.user.is_authenticated:
        return redirect('my-passwords')
    
    return redirect('homepage')


def sign_in(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            #if user is active:
            if user.is_active:
                login(request, user)
                return redirect('my-passwords')
            
            else:
                messages.info(request, 'Please verify your account first')
                user.delete()
        else:
            messages.info(request, 'Username or password is incorrect')

    return render(request, 'main/sign-in.html')


def sign_up(request):

    if request.user.is_authenticated:
        return redirect('my-passwords')

    form = CreateUserForm()

    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            user_form = form.save()
            user_form.is_active = False
            user_form.save()
            profile = Profile.objects.create(user=user_form)
            secret = generate_secret_key()
            profile.secret_key = secret
            profile.save()

            request.session['otp_user_id'] = user_form.id
            x = datetime.now()
            random = pyotp.random_base32()
            hotpp = pyotp.HOTP(random)
            one_time_password = hotpp.at(x.microsecond)
            message = '\nThe 6 digit OTP is: ' + str(
            one_time_password) + '\n\nThis is a system-generated response for your OTP. Please do not reply to this email.'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user_form.email]
            subject = 'Your OTP for BreakingByte Password Manager'
            send_mail(subject, message, email_from, recipient_list)
            request.session["random"] = random
            request.session["x_value"] = x.isoformat()
            return redirect("/otp")   

        else:
            return render(request, 'main/sign-up.html', {'form': form})

    context = {'form': form}
    return render(request, 'main/sign-up.html', context)


def otp(request):

    if request.user.is_authenticated:
        return redirect('my-passwords')
    
    if 'otp_user_id' not in request.session:
        return redirect('home')
      
    if request.method == 'GET':
        user = User.objects.get(id=request.session['otp_user_id'])
        args = {"email": user.email}
        return render(request, "main/otp.html", args)
    
    if request.method == 'POST':
        otp_from_page = request.POST.get('otp')
        user_id = request.session['otp_user_id']
        request.session.pop('otp_user_id')
        user = User.objects.get(id=user_id)
        profile = Profile.objects.get(user=user)

        x_iso= request.session["x_value"]
        x = datetime.fromisoformat(x_iso)
        random = request.session["random"]
        hotpp = pyotp.HOTP(random)
        one_time_password = hotpp.at(x.microsecond)
        request.session.pop("x_value")
        request.session.pop("random")
        post_datetime = datetime.now()
        diff = post_datetime - x
        sec = diff.total_seconds()
        print("seconds = ",sec)
  
        if (otp_from_page == one_time_password) and (sec < 120):
            user.is_active = True
            user.save()

            # Generate QR code
            qr_code = qrcode.QRCode(version=None, box_size=10, border=4)
            totp = pyotp.TOTP(profile.secret_key)
            qr_code.add_data(totp.provisioning_uri(profile.user.email, issuer_name="BreakingByte"))
            qr_code.make(fit=True)

            # Generate QR code image
            img = qr_code.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            img_byte = buffer.getvalue()
            
            img_base64 = base64.b64encode(img_byte).decode('utf-8')

            # Render 2FA setup page with QR code image and secret key
            return render(request, 'main/2fa_setup.html', {'img_base64': img_base64, 'secret_key': profile.secret_key})
            
        else:
            profile.delete()
            user.delete()
            #messages.info(request, 'Invalid OTP')
            return HttpResponse("Invalid OTP. Please try again.")

    return render(request, 'main/otp.html')

    # if request.method == "POST":
    #     print(request.POST.get('otp'))

    # return render(request, 'main/otp.html')


@login_required(login_url='sign-in')
def sign_out(request):
    logout(request)
    return redirect('home')


@login_required(login_url='sign-in')
def generate(request):
    if request.user.is_authenticated:        
        if request.method == 'POST':
            length = request.POST.get('length')
            #if length is not a number
            if not length.isdigit():
                return render(request, 'main/generate.html', {'password': 'Length must be a number!'})
            uppercase = request.POST.get('uppercase')
            lowercase = request.POST.get('lowercase')
            numbers = request.POST.get('numbers')
            special_chars = request.POST.get('symbols')
            password = generate_password(
                int(length), uppercase, lowercase, special_chars, numbers)
            
            profile=Profile.objects.get(user=request.user)
            profile.xp = profile.xp + give_password_strength_xp(password)
            profile.save()

            return render(request, 'main/generate.html', {'password': password, 'length': length, 'uppercase': uppercase, 'lowercase': lowercase, 'numbers': numbers, 'special_chars': special_chars})
        
        return render(request, 'main/generate.html')

    else:
        return redirect('sign-in')


@login_required(login_url='sign-in')
def my_passwords(request):

    if request.user.is_authenticated:
        if request.method == 'POST':
            if request.POST.get('delete'):
                password_id = request.POST.get('delete')
                password_detail = Password_Details.objects.get(id=password_id)
                if password_detail.user == request.user:
                    password_detail.delete()
                    return redirect('my-passwords')
                else:
                    return HttpResponse("You can't delete this password!")
                
            if request.POST.get('view-password'):                                        
                request.session['id_pass'] = request.POST.get('view-password')
                return redirect('two_fa')   

            
            if request.POST.get('search'):
                search = request.POST.get('search')
                # remove spaces from search from the end
                search = search.rstrip().lstrip()
                passwords = Password_Details.objects.filter(
                    user=request.user, website_name__icontains=search)
                if passwords:
                    for password in passwords:
                        password.website_name = password.website_name.capitalize()
                        password.website_notes = password.website_notes.capitalize()
                        password.website_password = ''
                        password.website_link = "https://www.google.com/s2/favicons?sz=128&domain_url=" + \
                            password.website_link

                    return render(request, 'main/my-passwords.html', {'passwords': passwords})
                else:
                    return render(request, 'main/my-passwords.html')
                
            if request.POST.get('share'):
                password_id = request.POST.get('share')
                request.session['id_pass_sharing'] = password_id
                return redirect('share-password')

        try:
            passwords = Password_Details.objects.filter(user=request.user)
        except Password_Details.DoesNotExist:
            return HttpResponse("You have no passwords saved yet!")

        # if passwords is not empty
        if passwords:

            for password in passwords:
                # capitalize the first letter of the website name
                password.website_name = password.website_name.capitalize()
                password.website_notes = password.website_notes.capitalize()
                password.website_password = ''
                password.website_link = "https://www.google.com/s2/favicons?sz=128&domain_url=" + \
                    password.website_link

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

            errors = []

            # check conditions for website name, link, username and password and notes
            if not website_name:
                errors.append('Website name is required!')
            if not website_link:
                errors.append('Website link is required!')
            if not website_username:
                errors.append('Website username is required!')
            if not website_password:
                errors.append('Website password is required!')
            if not website_notes:
                errors.append('Website notes is required!')

            # url_form_field = models.URLField()
            # try:
            #     url = url_form_field.clean(website_link)
            # except ValidationError:
            #     errors.append('Website link is not valid!')

            if errors:
                return render(request, 'main/add-password.html', {'errors': errors})
            
            # encrypt the password

            website_password = encrypt(
                settings.SECRET_HERE.encode(), website_password.encode())
            website_password = encrypt(
                settings.SECRET_HERE.encode(), website_password.encode())
            user = User.objects.get(username=request.user)
            password = Password_Details(user=user, website_name=website_name, website_link=website_link,
                                        website_username=website_username, website_password=website_password, website_notes=website_notes)
            password.save()

            profile = Profile.objects.get(user=request.user)
            profile.xp = profile.xp + 10 # add 10 xp for adding a password
            profile.save()
            
            return redirect('my-passwords')

        return render(request, 'main/add-password.html')
    else:
        return redirect('sign-in')


@login_required(login_url='sign-in')
def view_edit_password(request):

    if request.user.is_authenticated:
            if 'edit' in request.session:
                request.session.pop('edit')
            if 'website_link' in request.session:
                request.session.pop('website_link')
            if 'website_username' in request.session:
                request.session.pop('website_username')
            if 'website_password' in request.session:
                request.session.pop('website_password')

            if request.method == 'POST':
                if request.POST.get('edit'):
                    password_id = request.POST.get('edit')           

                    if Password_Details.objects.filter(id=password_id).exists():
                        password_detail = Password_Details.objects.get(id=password_id)
                        if password_detail.user == request.user:

                            # check if request.post website link, username and password are not empty
                            if not request.POST.get('website-link'):
                                return HttpResponse("Website link is required!")
                            if not request.POST.get('website-username'):
                                return HttpResponse("Website username is required!")
                            if not request.POST.get('website-password'):
                                return HttpResponse("Website password is required!")
                            
                            request.session['id_pass'] = password_id
                            request.session['edit'] = True
                            request.session['website_link'] = request.POST.get('website-link')
                            request.session['website_username'] = request.POST.get('website-username')
                            request.session['website_password'] = request.POST.get('website-password')
                            
                            return redirect('two_fa')
                        else:
                            return HttpResponse("You can't edit this password!")
                    else:
                        return HttpResponse("Password does not exist!")

            else:

                # if request session contains id_pass
                id_pass = None

                if 'id_pass' in request.session:
                    id_pass = request.session['id_pass']
                    # pop the id_pass from the session
                    request.session.pop('id_pass')
                    password_details = Password_Details.objects.get(id=id_pass)
                    if request.user == password_details.user or password_details.shared_with.contains(request.user):

                        if password_details.viewable == False:
                            return HttpResponse("You must verify with 2FA before viewing this password.")
                        
                        else:
                            password_details.viewable = False
                            password_details.save()
                        
                            password_details.website_name = password_details.website_name.capitalize()
                            password_details.website_notes = password_details.website_notes.capitalize()
                            password_details.website_password = decrypt(
                                settings.SECRET_HERE.encode(), password_details.website_password)
                            password_details.website_password = decrypt(
                                settings.SECRET_HERE.encode(), password_details.website_password)
                            


                            return render(request, 'main/view-edit-password.html', {'password': password_details})
                    
                    else:
                        return redirect('my-passwords')

                else:
                    return redirect('my-passwords')
        
    else:
        return redirect('sign-in')
    

@login_required(login_url='sign-in')
def share_password(request):
    if request.user.is_authenticated:
        
        if request.method == 'POST':
            
            username_to_share_to = request.POST.get('sharing-to-username')
            username_to_share_to = username_to_share_to.rstrip().lstrip()           

            try:
                user_to_share = User.objects.get(username=username_to_share_to)
            except User.DoesNotExist:
                return HttpResponse("User does not exist!")
            
            #check if the user is trying to share with themselves
            if request.user == user_to_share:
                return HttpResponse("You cannot share a password with yourself!")
            
            try:
                password_details = Password_Details.objects.get(id=request.POST.get("password-id"))
            except Password_Details.DoesNotExist:
                return HttpResponse("Password does not exist!")

            if request.user != password_details.user:
                return HttpResponse("You are not authorized to share this password!")
            
            # print("Password details: ", password_details.website_name)
            # model conatins shared_with = models.ManyToManyField(User, related_name='shared_with', blank=True), so we can use add
            password_details.shared_with.add(user_to_share)
            password_details.save()

            profile = Profile.objects.get(user=request.user)
            profile.xp = profile.xp + 15 # add 15 xp for sharing a password

            # print("Shared with: ", password_details.shared_with.all())
            return redirect('share')
        
        else:
            if 'id_pass_sharing' in request.session:
                id_pass_sharing = request.session['id_pass_sharing']
                # pop the id_pass_sharing from the session
                request.session.pop('id_pass_sharing')
                password_details = Password_Details.objects.get(id=id_pass_sharing)
                password_details_needed = {}
                if request.user != password_details.user: # if the user is not the owner of the password
                    return redirect('my-passwords')
                else:
                    password_details_needed = {
                        'website_name': password_details.website_name.capitalize(),
                        'website_link': "https://www.google.com/s2/favicons?sz=128&domain_url=" + password_details.website_link,
                        'password_id': password_details.id,
                    }
                return render(request, 'main/share-password.html', {'password_details_needed': password_details_needed})                        
            else:
                return redirect('my-passwords')
    else:
        return redirect('sign-in')
    
@login_required(login_url='sign-in')
def share(request):

    if request.user.is_authenticated:

        search = False
        search_text = None

        if request.method == 'POST':

            # if request.POST.get('view-password-user'):
            #     request.session['id_pass'] = request.POST.get('view-password-user')
            #     return redirect('view-edit-password')
            
            if request.POST.get('view-password-user'):
    
                request.session['id_pass'] = request.POST.get('view-password-user')
                return redirect('two_fa')
   
            
            if request.POST.get('stop-sharing'):
                password_details = Password_Details.objects.get(id=request.POST.get('stop-sharing'))
                if request.user == password_details.user:
                    password_details.shared_with.clear()
                    return redirect('share')
                else:
                    return HttpResponse("You are not authorized to stop sharing this password!")

            # if request.POST.get('view-password-shared'):
            #     request.session['id_pass'] = request.POST.get('view-password-shared')
            #     return redirect('view-edit-password')

            if request.POST.get('view-password-shared'):

                request.session['id_pass'] = request.POST.get('view-password-shared')
                return redirect('two_fa')

            if request.POST.get('search'):
                search = True
                search_text = request.POST.get('search')
                search_text = search_text.rstrip().lstrip()                  


        # get all passwords where user shared_with is present

        if not search:
            user_passwords = Password_Details.objects.filter(user=request.user, shared_with__isnull=False)
        else:
            user_passwords = Password_Details.objects.filter(user=request.user, shared_with__isnull=False, website_name__icontains=search_text)
        
        # remove duplicates
        user_passwords = user_passwords.distinct()

        if user_passwords:
            for password in user_passwords:
                if password.shared_with.all(): # if shared with is not empty
                    # capitalize the first letter of the website name
                    password.website_name = password.website_name.capitalize()
                    password.website_notes = password.website_notes.capitalize()
                    password.website_password = ''
                    password.website_link = "https://www.google.com/s2/favicons?sz=128&domain_url=" + password.website_link
                
                        
        if not search:
            shared_with_me_passwords = Password_Details.objects.filter(shared_with=request.user)
        else:
            shared_with_me_passwords = Password_Details.objects.filter(shared_with=request.user, website_name__icontains=search_text)

        if shared_with_me_passwords:
            for password in shared_with_me_passwords:
                # capitalize the first letter of the website name
                password.website_name = password.website_name.capitalize()
                password.website_notes = password.website_notes.capitalize()
                password.website_password = ''
                password.website_link = "https://www.google.com/s2/favicons?sz=128&domain_url=" + password.website_link
        
        return render(request, 'main/share.html', {'passwords': user_passwords, 'shared_passwords': shared_with_me_passwords})

    else:
        return redirect('sign-in')
    
@login_required(login_url='sign-in')
def two_fa(request):
    if request.user.is_authenticated:
        if request.method == 'POST':

            otp=request.POST.get('otp')
            # Verify OTP
            secret_key = request.user.profile.secret_key
            if secret_key:
                is_valid = verify_totp(secret_key, otp)
                if not is_valid:
                    password_id = request.session.get('id_pass')
                    #pop id_pass from session
                    request.session.pop('id_pass')
                    try:
                        password_detail = Password_Details.objects.get(id=password_id)
                        password_detail.viewable = False
                        password_detail.save()
                        return HttpResponse("Invalid OTP! Try again.")
                    except Password_Details.DoesNotExist:
                        return HttpResponse("Password does not exist.")
                    
                else:
                    password_id = request.session.get('id_pass')
                    try:
                        password_detail = Password_Details.objects.get(id=password_id)
                        password_detail.viewable = True

                        if request.session.get('edit'):
                            website_link = request.session.get('website_link')
                            website_username = request.session.get('website_username')
                            website_password = request.session.get('website_password')

                            website_password = encrypt(settings.SECRET_HERE.encode(), website_password.encode())
                            website_password = encrypt(settings.SECRET_HERE.encode(), website_password.encode())


                            password_detail.website_link = website_link
                            password_detail.website_username = website_username
                            password_detail.website_password = website_password
                        
                        password_detail.save()                                                    
                        #request.session['id_pass'] = request.POST.get('view-password-user')
                        return redirect('view-edit-password')
                    except Password_Details.DoesNotExist:
                        request.session.pop('id_pass')
                        return HttpResponse("Password does not exist.")
            else:
                return HttpResponse("You must setup 2FA before viewing passwords.")
        else:
            if 'id_pass' in request.session:
                id_pass = request.session['id_pass']
                # pop the id_pass_sharing from the session
                #request.session.pop('id_pass_sharing')
                try:
                    password_details = Password_Details.objects.get(id=id_pass)
                except Password_Details.DoesNotExist:
                    request.session.pop('id_pass')
                    return HttpResponse("Password does not exist.")
                
                password_details_needed = {}
                if request.user != password_details.user and not(password_details.shared_with.contains(request.user)):
                    request.session.pop('id_pass')
                    return redirect('my-passwords')
                else:
                    password_details_needed = {
                        'website_name': password_details.website_name.capitalize(),
                        'website_link': "https://www.google.com/s2/favicons?sz=128&domain_url=" + password_details.website_link,

                    }
                return render(request, 'main/two_fa.html', {'password_details_needed': password_details_needed})                        
            else:
                return redirect('my-passwords')
            
    else:
        return redirect('sign-in')


@login_required(login_url='sign-in')
def rewards(request):

    if request.user.is_authenticated:
        profile = Profile.objects.get(user=request.user)
        xp = profile.xp

        level, xp_percentage = calculate_level(xp)

        return render(request, 'main/rewards.html', {'level': level, 'xp_percentage': xp_percentage, 'xp': xp})
    else:
        return redirect('sign-in')