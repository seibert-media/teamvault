// Import our custom CSS
import '../scss/base.scss'

import * as bootstrap from 'bootstrap' // TODO: Specify which plugins we really need
import $ from 'jquery'
import * as Notyf from 'notyf'
import * as Card from 'card'
import 'select2'
import '../scss/select2.scss'

window.bootstrap = bootstrap

window.$ = $
window.jQuery = $

window.Notyf = Notyf

window.Card = Card

// Patch width. See https://github.com/select2/select2/issues/3278
$.fn.select2.defaults.set("width", "100%")
$.fn.select2.defaults.set("theme", "bootstrap-5")

// Patch backspace on select2 4.X. See https://github.com/select2/select2/issues/3354
$.fn.select2.amd.require(['select2/selection/search'], function (Search) {
  Search.prototype.searchRemoveChoice = function (decorated, item) {
    this.trigger('unselect', {
      data: item
    });

    this.$search.val('');
    this.handleSearch();
  };
}, null, true);

