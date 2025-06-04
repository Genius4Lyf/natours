import axios from 'axios';
import { showAlert } from './alert';

const stripe = Stripe(
  'pk_test_51RRKVqBRUikKdFknNhtkpw5YRRr9E9musoZggC5OmurniHc0RWHGBsSs0nGzXCv3Ko6Ty9lEUH6lCB3mrqPKqxss00U8RbtIC2',
);

export const bookTour = async (tourId) => {
  try {
    // 1. Get checkout session form API
    const session = await axios(`/api/v1/bookings/checkout-session/${tourId}`);
    console.log(session);
    // 2. Create checkout form + charge the credit card
    await stripe.redirectToCheckout({
      sessionId: session.data.session.id,
    });
  } catch (error) {
    showAlert('error', error);
  }
};
