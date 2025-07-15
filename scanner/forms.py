from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from django import forms

SCAN_TYPE_CHOICES = [
    ('ping', 'Ping'),
    ('nmap', 'Nmap Scan'),
    ('ping_sweep', 'Ping Sweep (with Hostname)'),
    ('nmap_ping_sweep', 'Nmap Ping Sweep'),
]

class ScanForm(forms.Form):
    target = forms.CharField(
        label='Target IP or Network',
        max_length=100,
        widget=forms.TextInput(attrs={
            'placeholder': 'e.g. 192.168.1.1 or 192.168.1.0/24',
            'class': 'form-control'
        }),
        help_text='Enter an IP address or network range (CIDR) for sweep.'
    )
    scan_type = forms.ChoiceField(
        label='Scan Type',
        choices=SCAN_TYPE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        initial='ping'
    )


class UserRegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
