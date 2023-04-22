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

import random
import string

import pyotp
import qrcode

def generate_secret_key():
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.secret

def verify_totp(secret_key, token):
    totp = pyotp.TOTP(secret_key)
    return totp.verify(token)



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
        return redirect('my-passwords')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('my-passwords')
        else:
            messages.info(request, 'Username OR password is incorrect')

    return render(request, 'main/sign-in.html')

def sign_in(request):
    return redirect('home')


def sign_up(request):

    form = CreateUserForm()

    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            user_form = form.save()
            profile = Profile.objects.create(user=user_form)
            profile.secret_key = generate_secret_key()
            profile.save()

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
            return render(request, 'main/sign-up.html', {'form': form})

    context = {'form': form}
    return render(request, 'main/sign-up.html', context)


@login_required(login_url='sign-in')
def sign_out(request):
    logout(request)
    return redirect('home')


@login_required(login_url='sign-in')
def generate(request):
    if request.user.is_authenticated:        
        if request.method == 'POST':
            length = request.POST.get('length')
            uppercase = request.POST.get('uppercase')
            lowercase = request.POST.get('lowercase')
            numbers = request.POST.get('numbers')
            special_chars = request.POST.get('symbols')
            password = generate_password(
                int(length), uppercase, lowercase, special_chars, numbers)
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

            website_password = encrypt(
                settings.SECRET_HERE.encode(), website_password.encode())
            website_password = encrypt(
                settings.SECRET_HERE.encode(), website_password.encode())
            user = User.objects.get(username=request.user)
            password = Password_Details(user=user, website_name=website_name, website_link=website_link,
                                        website_username=website_username, website_password=website_password, website_notes=website_notes)
            password.save()
            return HttpResponse("Password added successfully!")

        return render(request, 'main/add-password.html')
    else:
        return redirect('sign-in')


@login_required(login_url='sign-in')
def view_edit_password(request):

    if request.user.is_authenticated:
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

@login_required(login_url='sign-in')
def share_password(request):
    if request.user.is_authenticated:
        # if request session contains id_pass
        id_pass = None

        if request.method == 'POST':
            
            username_to_share_to = request.POST.get('sharing-to-username')
            username_to_share_to = username_to_share_to.rstrip().lstrip()
            print("YOO!!!!!!!!!!!!!!!", username_to_share_to)
            

            try:
                user_to_share = User.objects.get(username=username_to_share_to)
            except User.DoesNotExist:
                return HttpResponse("User does not exist!")

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
            # print("Shared with: ", password_details.shared_with.all())
            return redirect('my-passwords')
        
        else:
            if 'id_pass_sharing' in request.session:
                id_pass_sharing = request.session['id_pass_sharing']
                # pop the id_pass_sharing from the session
                request.session.pop('id_pass_sharing')
                password_details = Password_Details.objects.get(id=id_pass_sharing)
                password_details_needed = {}
                if request.user != password_details.user:
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
                        return HttpResponse("Invalid OTP")
                    except Password_Details.DoesNotExist:
                        return HttpResponse("Password does not exist.")
                    
                else:
                    password_id = request.session.get('id_pass')
                    try:
                        password_detail = Password_Details.objects.get(id=password_id)
                        password_detail.viewable = True
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


# def two_fa_page(request):
#     return render(request, 'main/2fa_setup.html')