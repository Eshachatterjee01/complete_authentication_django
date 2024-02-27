from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self,decode_user,timestamp):
        return (six.text_type(decode_user.pk)+ six.text_type(timestamp)+six.text_type(decode_user.is_active))
    
generate_token=TokenGenerator()