import { HttpException, HttpStatus } from '@nestjs/common';
import * as sgMail from '@sendgrid/mail';

export const send = async (
  to: string,
  subject: string,
  html: string,
): Promise<void> => {
  try {
    if (!process.env.SENDGRID_API_KEY) {
      return;
    }

    sgMail.setApiKey(process.env.SENDGRID_API_KEY);

    await sgMail.send({
      to,
      from: {
        email: 'noreply@defless.fr', // Change to your verified sender
        name: 'Ma ville accessible',
      },
      subject,
      html,
    });
  } catch (error) {
    console.log(error);
    throw new HttpException('Server error', HttpStatus.INTERNAL_SERVER_ERROR);
  }
};
