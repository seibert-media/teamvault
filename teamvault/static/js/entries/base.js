// Import vendor tom select css
import 'tom-select/dist/css/tom-select.bootstrap5.min.css';
// Import our custom CSS
import '../../scss/base.scss'

import * as bootstrap from 'bootstrap'
import $ from 'jquery'
import {TempusDominus} from '@eonasdan/tempus-dominus'
import TomSelect from 'tom-select';

import {initZxcvbn} from '../zxcvbn.ts'

import * as teamvault from '../utils'
import * as otp from '../otp'

// Modules
import {initThemeEarly} from '../modules/theme'
import {initThemeToggle} from '../modules/theme-toggle'
import {initTooltips} from '../modules/tooltips'
import {initNotifications} from '../modules/notifications'
import {initSearch} from '../modules/search'

// Theme must run before DOM is ready to prevent flash
initThemeEarly()

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

// Card
window.Card = require('card')

// ClipboardJS — keep global for now, used by secret detail inline scripts
import ClipboardJS from "clipboard";
window.ClipboardJS = ClipboardJS

// Tempus Dominus — keep global for HTMX-loaded share modal
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

// tom-select
window.TomSelect = TomSelect

// Initialize modules on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle()
  initTooltips()
  initNotifications()
  initSearch()
})
