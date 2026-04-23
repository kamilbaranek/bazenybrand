const header = document.querySelector(".site-header");
const menuToggle = document.querySelector(".menu-toggle");
const nav = document.querySelector(".site-nav");
const navLinks = Array.from(document.querySelectorAll(".site-nav a"));
const sections = Array.from(document.querySelectorAll("[data-section]"));
const revealItems = Array.from(document.querySelectorAll(".reveal"));
const heroScrollHint = document.querySelector(".hero-scroll-hint");
const contactForm = document.querySelector(".contact-form");
const recaptchaTokenInput = document.querySelector('input[name="recaptcha_token"]');
const galleryButtons = Array.from(document.querySelectorAll("[data-gallery-index]"));
const lightbox = document.querySelector("[data-lightbox]");
const lightboxImage = document.querySelector("[data-lightbox-image]");
const lightboxCaption = document.querySelector("[data-lightbox-caption]");
const lightboxCounter = document.querySelector("[data-lightbox-counter]");
const lightboxClose = document.querySelector("[data-lightbox-close]");
const lightboxPrev = document.querySelector("[data-lightbox-prev]");
const lightboxNext = document.querySelector("[data-lightbox-next]");
const realizationGalleryItems = [
  {
    src: "assets/realizace/realizace-01.jpg",
    alt: "Dokončený bazén se šedou fólií a napuštěnou vodou",
    caption: "Dokončená realizace fóliového bazénu se šedým povrchem.",
  },
  {
    src: "assets/realizace/realizace-02.jpg",
    alt: "Prázdný šedý bazén se schodištěm a okolní dlažbou",
    caption: "Hotový šedý bazén se schodištěm a okolní dlažbou.",
  },
  {
    src: "assets/realizace/realizace-03.jpg",
    alt: "Zapuštěný bazén ve fázi dokončení u domu",
    caption: "Zapuštěný bazén ve fázi dokončení technologie.",
  },
  {
    src: "assets/realizace/realizace-04.jpg",
    alt: "Prázdný bazén připravený před napuštěním",
    caption: "Prázdný bazén připravený před napuštěním.",
  },
  {
    src: "assets/realizace/realizace-05.jpg",
    alt: "Čistý bazénový skelet před finálním zprovozněním",
    caption: "Čistý bazénový skelet před finálním zprovozněním.",
  },
  {
    src: "assets/realizace/realizace-06.jpg",
    alt: "Montáž zapuštěného bazénu s pojezdem zastřešení",
    caption: "Montáž zapuštěného bazénu s pojezdem zastřešení.",
  },
  {
    src: "assets/realizace/realizace-07.jpg",
    alt: "Realizace bazénu s fólií ve fázi instalace",
    caption: "Realizace bazénu s fólií ve fázi instalace.",
  },
  {
    src: "assets/realizace/realizace-08.jpg",
    alt: "Bazén s čistou modrou vodou po servisním zásahu",
    caption: "Čistá voda po servisním zásahu.",
  },
  {
    src: "assets/realizace/realizace-09.jpg",
    alt: "Modrý bazén po vyčištění a napuštění",
    caption: "Modrý bazén po vyčištění a napuštění.",
  },
  {
    src: "assets/realizace/realizace-10.jpg",
    alt: "Bazén před čištěním a servisním zásahem",
    caption: "Bazén před čištěním a servisním zásahem.",
  },
  {
    src: "assets/realizace/realizace-11.jpg",
    alt: "Znečištěný bazén před zahájením servisu",
    caption: "Znečištěný bazén před zahájením servisu.",
  },
  {
    src: "assets/realizace/realizace-12.jpg",
    alt: "Bazén před vyčištěním ve venkovní zahradě",
    caption: "Bazén před vyčištěním ve venkovní zahradě.",
  },
  {
    src: "assets/realizace/realizace-13.jpg",
    alt: "Vyčištěný bazén pod zastřešením",
    caption: "Vyčištěný bazén pod zastřešením.",
  },
  {
    src: "assets/realizace/realizace-14.jpg",
    alt: "Bazén se zastřešením před servisním zásahem",
    caption: "Bazén se zastřešením před servisním zásahem.",
  },
  {
    src: "assets/realizace/realizace-15.jpg",
    alt: "Koláž před a po čištění bazénu",
    caption: "Koláž před a po čištění bazénu.",
  },
];
let lastScrollY = window.scrollY;
let activeGalleryIndex = 0;
let lastFocusedElement = null;
let recaptchaSubmitInProgress = false;

const closeMenu = () => {
  if (!header || !menuToggle) {
    return;
  }

  header.classList.remove("is-open");
  menuToggle.setAttribute("aria-expanded", "false");
};

const normalizeGalleryIndex = (index) => {
  const itemCount = realizationGalleryItems.length;

  return ((index % itemCount) + itemCount) % itemCount;
};

const setLightboxImage = (index) => {
  if (!lightboxImage || !lightboxCaption || !lightboxCounter) {
    return;
  }

  activeGalleryIndex = normalizeGalleryIndex(index);

  const item = realizationGalleryItems[activeGalleryIndex];

  lightboxImage.src = item.src;
  lightboxImage.alt = item.alt;
  lightboxCaption.textContent = item.caption;
  lightboxCounter.textContent = `${activeGalleryIndex + 1} / ${realizationGalleryItems.length}`;
};

const openLightbox = (index) => {
  if (!lightbox) {
    return;
  }

  lastFocusedElement = document.activeElement;
  setLightboxImage(index);
  lightbox.hidden = false;
  lightbox.setAttribute("aria-hidden", "false");
  document.body.classList.add("is-lightbox-open");
  lightboxClose?.focus();
};

const closeLightbox = () => {
  if (!lightbox || lightbox.hidden) {
    return;
  }

  lightbox.hidden = true;
  lightbox.setAttribute("aria-hidden", "true");
  document.body.classList.remove("is-lightbox-open");
  lightboxImage?.removeAttribute("src");

  if (lastFocusedElement instanceof HTMLElement) {
    lastFocusedElement.focus();
  }
};

const showPreviousGalleryImage = () => {
  setLightboxImage(activeGalleryIndex - 1);
};

const showNextGalleryImage = () => {
  setLightboxImage(activeGalleryIndex + 1);
};

if (menuToggle && header && nav) {
  menuToggle.addEventListener("click", () => {
    const isOpen = header.classList.toggle("is-open");
    menuToggle.setAttribute("aria-expanded", String(isOpen));
  });
}

navLinks.forEach((link) => {
  link.addEventListener("click", closeMenu);
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeMenu();
    closeLightbox();
    return;
  }

  if (!lightbox || lightbox.hidden) {
    return;
  }

  if (event.key === "ArrowLeft") {
    event.preventDefault();
    showPreviousGalleryImage();
  }

  if (event.key === "ArrowRight") {
    event.preventDefault();
    showNextGalleryImage();
  }
});

galleryButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const galleryIndex = Number.parseInt(button.dataset.galleryIndex || "0", 10);

    openLightbox(galleryIndex);
  });
});

lightbox?.addEventListener("click", (event) => {
  if (event.target === lightbox) {
    closeLightbox();
  }
});

lightboxClose?.addEventListener("click", closeLightbox);
lightboxPrev?.addEventListener("click", showPreviousGalleryImage);
lightboxNext?.addEventListener("click", showNextGalleryImage);

if (contactForm && recaptchaTokenInput) {
  contactForm.addEventListener("submit", (event) => {
    const siteKey = window.contactFormConfig?.recaptchaSiteKey;

    if (recaptchaSubmitInProgress || !siteKey || !window.grecaptcha) {
      return;
    }

    event.preventDefault();

    window.grecaptcha.ready(() => {
      window.grecaptcha
        .execute(siteKey, { action: "contact" })
        .then((token) => {
          recaptchaTokenInput.value = token;
          recaptchaSubmitInProgress = true;
          contactForm.submit();
        })
        .catch(() => {
          recaptchaSubmitInProgress = true;
          contactForm.submit();
        });
    });
  });
}

const setActiveLink = (id) => {
  navLinks.forEach((link) => {
    const isActive = link.getAttribute("href") === `#${id}`;
    link.classList.toggle("is-active", isActive);

    if (isActive) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });
};

const updateHeroScrollHint = () => {
  if (!heroScrollHint) {
    return;
  }

  const currentScrollY = window.scrollY;
  const isAtTop = currentScrollY <= 20;
  const isScrollingDown = currentScrollY > lastScrollY;

  if (isAtTop) {
    heroScrollHint.classList.remove("is-hidden");
  } else if (isScrollingDown) {
    heroScrollHint.classList.add("is-hidden");
  }

  lastScrollY = currentScrollY;
};

updateHeroScrollHint();
window.addEventListener("scroll", updateHeroScrollHint, { passive: true });

if ("IntersectionObserver" in window) {
  const sectionObserver = new IntersectionObserver(
    (entries) => {
      const visibleEntries = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio);

      if (visibleEntries.length > 0) {
        setActiveLink(visibleEntries[0].target.id);
      }
    },
    {
      rootMargin: "-25% 0px -45% 0px",
      threshold: [0.2, 0.4, 0.65],
    }
  );

  sections.forEach((section) => {
    if (section.id) {
      sectionObserver.observe(section);
    }
  });

  const revealObserver = new IntersectionObserver(
    (entries, observer) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    {
      threshold: 0.14,
      rootMargin: "0px 0px -8% 0px",
    }
  );

  revealItems.forEach((item) => revealObserver.observe(item));
} else {
  revealItems.forEach((item) => item.classList.add("is-visible"));
}
