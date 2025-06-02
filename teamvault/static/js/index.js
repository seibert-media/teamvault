// Import our custom CSS
import '../scss/base.scss'

import * as bootstrap from 'bootstrap' // TODO: Specify which plugins we really need
import $ from 'jquery'
import {Notyf} from 'notyf';
import 'notyf/notyf.min.css'
import autoCompleteJS from '@tarekraafat/autocomplete.js';
import ClipboardJS from "clipboard";
import DOMPurify from 'dompurify';
import {TempusDominus} from '@eonasdan/tempus-dominus'

import {initZxcvbn} from './zxcvbn.ts'

import * as teamvault from './utils'
import * as otp from './otp'

window.otp = otp
window.teamvault = teamvault

// Bootstrap
window.bootstrap = bootstrap

// HTMX
window.htmx = require('htmx.org')

// jQuery
window.$ = $
window.jQuery = $

//js qr scanner
window.qrScanner = require("jsqr")

// Bigtext
require('bigtext');

// Notyf
document.addEventListener('DOMContentLoaded', () => {
  // Notyf tries to hook to a body, which we don't have in this context yet.
  window.notyf = new Notyf({position: {x: 'right', y: 'top'}})
})

// Card
window.Card = require('card')

// ClipboardJS
window.ClipboardJS = ClipboardJS

// autocomplete.js
window.autoCompleteJS = autoCompleteJS

// DOMPurify (needed for autocompleteJS ajax queries)
window.DOMPurify = DOMPurify

// Tempus Dominus
window.TempusDominus = TempusDominus

// zxcvbn
window.zxcvbn = initZxcvbn()

// Select2
require('select2');
$.fn.select2.defaults.set("theme", "bootstrap-5")
$.fn.select2.defaults.set("width", "100%")  // https://github.com/select2/select2/issues/3278
$.fn.select2.amd.require(['select2/selection/search'], function (Search) {
  // Patch backspace on select2 4.X. See https://github.com/select2/select2/issues/3354
  Search.prototype.searchRemoveChoice = function (decorated, item) {
    this.trigger('unselect', {
      data: item
    });

    this.$search.val('');
    this.handleSearch();
  };
}, null, true);
