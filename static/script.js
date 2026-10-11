// Cart functionality using localStorage

function getCart() {
    return JSON.parse(localStorage.getItem('cart')) || [];
}

function saveCart(cart) {
    localStorage.setItem('cart', JSON.stringify(cart));
    updateCartCount();
}

function updateCartCount() {
    const cart = getCart();
    const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
    const countBadge = document.getElementById('cart-count');
    if (countBadge) {
        countBadge.innerText = totalItems;
    }
}

// size is optional for backward compatibility (e.g. homepage quick-add buttons
// that don't offer a size choice) and defaults to "Free Size".
function addToBag(id, title, price, image, size) {
    const itemSize = size || 'Free Size';
    let cart = getCart();

    // Same product but a different size is a separate cart line.
    let existingItem = cart.find(item => item.id === id && item.size === itemSize);

    if (existingItem) {
        existingItem.quantity += 1;
    } else {
        cart.push({
            id: id,
            title: title,
            price: price,
            image: image,
            size: itemSize,
            quantity: 1
        });
    }

    saveCart(cart);
    alert('✨ Item added to your bag successfully!');
}

// Initialize cart count badge on page load
document.addEventListener('DOMContentLoaded', () => {
    updateCartCount();
});
