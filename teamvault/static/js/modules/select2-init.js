import $ from 'jquery';

// select2 exports a factory in CommonJS mode — call it once to attach to $.fn
const select2Factory = require('select2');
select2Factory(window, $);

$.fn.select2.defaults.set("theme", "bootstrap-5");
$.fn.select2.defaults.set("width", "100%");  // https://github.com/select2/select2/issues/3278
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
