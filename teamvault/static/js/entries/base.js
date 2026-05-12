// Import vendor tom select css
import 'tom-select/dist/css/tom-select.bootstrap5.min.css';
// Import our custom CSS
import '../../scss/base.scss'

import * as bootstrap from 'bootstrap'
import $ from 'jquery'
import {createPopper} from '@popperjs/core'
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
window.Popper = {createPopper}
window.TomSelect = TomSelect

// Select2 initialization (attaches to $.fn, sets defaults, patches backspace)
import '../modules/select2-init';

// Initialize modules on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle()
  initTooltips()
  initNotifications()
  initSearch()
})
