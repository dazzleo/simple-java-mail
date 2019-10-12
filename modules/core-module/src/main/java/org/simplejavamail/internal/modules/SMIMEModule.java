package org.simplejavamail.internal.modules;

import org.simplejavamail.MailException;
import org.simplejavamail.api.email.AttachmentResource;
import org.simplejavamail.api.email.Email;
import org.simplejavamail.api.email.OriginalSmimeDetails;
import org.simplejavamail.api.internal.outlooksupport.model.OutlookMessage;
import org.simplejavamail.api.internal.smimesupport.builder.SmimeParseResult;
import org.simplejavamail.api.internal.smimesupport.model.SmimeDetails;
import org.simplejavamail.api.mailer.config.Pkcs12Config;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This interface only serves to hide the S/MIME implementation behind an easy-to-load-with-reflection class.
 */
public interface SMIMEModule {

	String NAME = "S/MIME module";

	/**
	 * @return The results of the S/MIME decryption of any compatible encrypted / signed attachments.
	 * @throws MailException when there was an error while decrypting a signed attachment.
	 */
	SmimeParseResult decryptAttachments(@Nonnull List<AttachmentResource> attachments, @Nonnull OutlookMessage outlookMessage, @Nullable Pkcs12Config pkcs12Config)
			throws MailException;

	/**
	 * @return The results of the S/MIME decryption of any compatible encrypted / signed attachments.
	 * @throws MailException when an error occurs while getting the {@code Content-Type} header from the give {@link MimeMessage}.
	 */
	SmimeParseResult decryptAttachments(@Nonnull List<AttachmentResource> attachments, @Nonnull MimeMessage mimeMessage, @Nullable Pkcs12Config pkcs12Config)
			throws MailException;

	/**
	 * @return A copy of given original 'true' attachments, with S/MIME encrypted / signed attachments replaced with the actual attachment.
	 * @throws MailException when there was an error while decrypting a signed attachment.
	 */
	@Nonnull
	List<AttachmentResource> decryptAttachments(@Nonnull List<AttachmentResource> attachments, @Nullable Pkcs12Config pkcs12Config, @Nonnull OriginalSmimeDetails messageSmimeDetails)
			throws MailException;

	/**
	 * @return Whether the given attachment is S/MIME signed / encrypted. Defers to {@code SmimeRecognitionUtil.isSmimeAttachment(..)}.
	 */
	boolean isSmimeAttachment(@Nonnull AttachmentResource attachment);

	/**
	 * @return The S/MIME mime type and signed who signed the attachment.
	 * <br>
	 * <strong>Note:</strong> the attachment is assumed to be a signed / encrypted {@link javax.mail.internet.MimeBodyPart}.
	 *
	 * @throws MailException See {@link #getSignedByAddress(AttachmentResource)}.
	 */
	@Nonnull
	SmimeDetails getSmimeDetails(@Nonnull AttachmentResource attachment)
			throws MailException;

	/**
	 * Delegates to {@link #getSignedByAddress(MimePart)}, where the datasource of the attachment is read completely as a MimeMessage.
	 * <br>
	 * <strong>Note:</strong> the attachment is assumed to be a signed / encrypted {@link javax.mail.internet.MimeBodyPart}.
	 *
	 * @throws MailException when reading all bytes of the given attachment (see {@link AttachmentResource#readAllBytes()}) or
	 * when an error occurs while getting input stream from attachment's data source.
	 */
	@Nullable
	String getSignedByAddress(@Nonnull AttachmentResource smimeAttachment)
			throws MailException;

	/**
	 * @return Who S/MIME signed /encrypted the attachment. This is indicated by the subject of the certificate (whom the certificate was 'issued to').
	 */
	@Nullable
	String getSignedByAddress(@Nonnull MimePart mimePart);

	boolean verifyValidSignature(@Nonnull MimeMessage mimeMessage, @Nonnull OriginalSmimeDetails messageSmimeDetails);

	@Nonnull
	MimeMessage signAndOrEncryptEmail(@Nonnull final Session session, @Nonnull final MimeMessage messageToProtect, @Nonnull final Email emailContainingSmimeDetails);

	@Nonnull
	MimeMessage signMessage(@Nullable Session session, @Nonnull MimeMessage message, @Nonnull Pkcs12Config pkcs12Config);

	@Nonnull
	MimeMessage encryptMessage(@Nullable Session session, @Nonnull MimeMessage message, @Nonnull X509Certificate certificate);
}
