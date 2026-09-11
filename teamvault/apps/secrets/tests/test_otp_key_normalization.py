from django.test import TestCase
from pyotp import TOTP

from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.forms import PasswordForm
from teamvault.apps.secrets.utils import extract_otp_params, normalize_otp_secret
from .utils import OTP_SECRET as CANONICAL_SECRET, grouped_otp_secret

NBSP = chr(0x00A0)
NARROW_NBSP = chr(0x202F)
ZWSP = chr(0x200B)
WORD_JOINER = chr(0x2060)
SOFT_HYPHEN = chr(0x00AD)
LEFT_TO_RIGHT_MARK = chr(0x200E)


PASTED_VARIANTS = {
    'plain': CANONICAL_SECRET,
    'lowercase': CANONICAL_SECRET.lower(),
    'spaces': grouped_otp_secret(' '),
    'lowercase spaces (google)': grouped_otp_secret(' ', CANONICAL_SECRET.lower()),
    'tabs': grouped_otp_secret('\t'),
    'newlines': grouped_otp_secret('\n'),
    'non-breaking spaces': grouped_otp_secret(NBSP),
    'narrow non-breaking spaces': grouped_otp_secret(NARROW_NBSP),
    'zero-width spaces': grouped_otp_secret(ZWSP),
    'word joiners': grouped_otp_secret(WORD_JOINER),
    'soft hyphens': grouped_otp_secret(SOFT_HYPHEN),
    'bidi marks': grouped_otp_secret(LEFT_TO_RIGHT_MARK),
    'hyphens': grouped_otp_secret('-'),
    'underscores': grouped_otp_secret('_'),
    'base32 padding': CANONICAL_SECRET + '====',
    'surrounding whitespace': f'  {CANONICAL_SECRET}\n',
}


class NormalizeOtpSecretTests(TestCase):
    def test_pasted_variants_reduce_to_the_same_secret(self):
        for label, pasted in PASTED_VARIANTS.items():
            with self.subTest(label):
                self.assertEqual(normalize_otp_secret(pasted).upper(), CANONICAL_SECRET)

    def test_base32_payload_is_left_intact(self):
        self.assertEqual(normalize_otp_secret(CANONICAL_SECRET), CANONICAL_SECRET)

    def test_normalized_variants_all_produce_the_same_code(self):
        expected = TOTP(CANONICAL_SECRET).now()
        for label, pasted in PASTED_VARIANTS.items():
            with self.subTest(label):
                self.assertEqual(TOTP(normalize_otp_secret(pasted)).now(), expected)


class ExtractOtpParamsTests(TestCase):
    def test_normalizes_the_secret_parameter(self):
        params = extract_otp_params(f'?secret={grouped_otp_secret("-")}&digits=6&algorithm=SHA1')
        self.assertEqual(params['secret'], CANONICAL_SECRET)
        self.assertEqual(params['digits'], '6')
        self.assertEqual(params['algorithm'], 'SHA1')

    def test_reads_an_otpauth_uri_regardless_of_parameter_order(self):
        for query in (
            f'secret={CANONICAL_SECRET}&issuer=ACME',
            f'issuer=ACME&secret={CANONICAL_SECRET}',
        ):
            with self.subTest(query):
                params = extract_otp_params(f'otpauth://totp/ACME:john?{query}')
                self.assertEqual(params['secret'], CANONICAL_SECRET)

    def test_empty_input_yields_no_params(self):
        self.assertEqual(extract_otp_params(''), {})


class PasswordFormOtpValidationTests(TestCase):
    @staticmethod
    def _form(otp_key_data):
        return PasswordForm(
            data={
                'name': 'example',
                'access_policy': AccessPolicy.DISCOVERABLE,
                'password': 'hunter2',
                'otp_key_data': otp_key_data,
            }
        )

    def test_accepts_every_pasted_variant(self):
        for label, pasted in PASTED_VARIANTS.items():
            with self.subTest(label):
                form = self._form(f'?secret={pasted}&digits=6&algorithm=SHA1&')
                self.assertTrue(form.is_valid(), form.errors)

    def test_rejects_a_secret_that_is_not_base32(self):
        form = self._form('?secret=not+a+valid+key!&digits=6&algorithm=SHA1&')
        self.assertFalse(form.is_valid())
        self.assertIn('otp_key_data', form.errors)
