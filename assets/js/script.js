document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const dropText = document.getElementById('dropText');
    const fileInput = document.getElementById('phpfile');

    const updateLabel = (files) => {
        if (!files || files.length === 0) {
            dropText.textContent = 'Arraste & solte ou clique para selecionar arquivos .php';
            return;
        }
        if (files.length === 1) {
            dropText.textContent = files[0].name;
        } else {
            dropText.textContent = `${files.length} arquivos selecionados`;
        }
    };

    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => updateLabel(fileInput.files));
    ['dragover', 'dragenter'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.add('hover');
        });
    });
    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.remove('hover');
        });
    });
    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length) {
            fileInput.files = files;
            updateLabel(files);
        }
    });

    const resultsContainer = document.querySelector('.results');
    if (resultsContainer) {
        resultsContainer.addEventListener('click', (e) => {
            const errorText = e.target.closest('.error-text');
            if (errorText) {
                const suggestion = errorText.nextElementSibling;
                if (suggestion && suggestion.classList.contains('suggestion')) {
                    const isVisible = suggestion.style.display === 'block';
                    suggestion.style.display = isVisible ? 'none' : 'block';
                }
            }
        });
    }

    window.addEventListener('pageshow', (e) => {
        if (e.persisted || (window.performance && performance.getEntriesByType("navigation")[0].type === "reload")) {
             const form = document.querySelector('form');
             if(form) form.reset();
             updateLabel(null);
        }
    });
});