import * as bootstrap from 'bootstrap';
import $ from 'jquery';

export function initAddeditCommon(config) {
  const searchableTooltip = config.dataset.searchableTooltip;
  const securelySavedTooltip = config.dataset.securelySavedTooltip;

  // Add searchable icons to labels
  const searchableLabels = document.getElementsByClassName('searchable');
  [...searchableLabels].map(el => {
    el.insertAdjacentHTML('beforeend', '<i class="fa fa-search fa-xs secret-extra-icon lh-1 align-middle"></i>');
    new bootstrap.Tooltip(el.querySelector('i'), {
      placement: 'top',
      title: searchableTooltip,
    });
  });

  // Add securely-saved icons to labels
  const securelySavedLabels = document.getElementsByClassName('securely-saved');
  [...securelySavedLabels].map(el => {
    el.insertAdjacentHTML('beforeend', '<i class="fa fa-lock fa-xs secret-extra-icon lh-1 align-middle"></i>');
    new bootstrap.Tooltip(el.querySelector('i'), {
      placement: 'top',
      title: securelySavedTooltip,
    });
  });

  // Access policy / share field toggle (only for new secrets)
  const isNew = config.dataset.isNew === 'true';
  if (isNew) {
    const sharedGroupsFieldId = config.dataset.sharedGroupsFieldId;
    const accessPolicyFieldId = config.dataset.accessPolicyFieldId;
    const accessPolicyAnyValue = '2';

    const sharedGroupsField = $(`#${sharedGroupsFieldId}`).select2();
    const accessPolicyField = document.getElementById(accessPolicyFieldId);
    const reasonFieldContainer = document.getElementById('reasonFieldContainer');
    const shareFieldsContainer = document.getElementById('initialShareFields');

    if (accessPolicyField) {
      accessPolicyField.addEventListener('change', (e) => {
        if (e.target.value === accessPolicyAnyValue) {
          shareFieldsContainer.setAttribute('hidden', '');
        } else {
          shareFieldsContainer.removeAttribute('hidden');
          shareFieldsContainer.scrollIntoView();
        }
      });
    }

    sharedGroupsField.on('change', function () {
      if (sharedGroupsField.val().length) {
        reasonFieldContainer.removeAttribute('hidden');
        reasonFieldContainer.scrollIntoView();
      } else {
        reasonFieldContainer.setAttribute('hidden', '');
      }
    });
  }
}
