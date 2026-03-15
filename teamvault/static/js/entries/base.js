// Import vendor tom select css
import 'tom-select/dist/css/tom-select.bootstrap5.min.css';
// Import our custom CSS
import '../../scss/base.scss'

import * as bootstrap from 'bootstrap'
import $ from 'jquery'
import {TempusDominus} from '@eonasdan/tempus-dominus'
import TomSelect from 'tom-select';

// Modules
import {initThemeEarly} from '../modules/theme'
import {initThemeToggle} from '../modules/theme-toggle'
import {initTooltips} from '../modules/tooltips'
import {initNotifications} from '../modules/notifications'
import {initSearch} from '../modules/search'

// Theme must run before DOM is ready to prevent flash
initThemeEarly()

// Globals needed by inline scripts and HTMX-loaded content
window.bootstrap = bootstrap
window.htmx = require('htmx.org')
window.$ = $
window.jQuery = $
window.TempusDominus = TempusDominus
window.TomSelect = TomSelect

// Bigtext (jQuery plugin, used by secret-detail-password.js via $.bigtext)
require('bigtext');

// Select2 (jQuery plugin, used by inline scripts in templates)
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

// Initialize modules on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle()
  initTooltips()
  initNotifications()
  initSearch()
})
