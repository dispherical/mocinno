// Email template taken from React Email official templates, 01-Barebones activation.tsx

import {
  Body,
  Button,
  Column,
  Container,
  Head,
  Heading,
  Html,
  Img,
  Link,
  Preview,
  Row,
  Section,
  Tailwind,
  Text,
} from "react-email";
import { barebonesBoxedTailwindConfig } from "./theme";

interface ApprovedEmailProps {
  username: string;
  url: string;
  ip?: string;
  ipv6?: string;
  template?: string;
}

export const ApprovedEmail = ({
  username,
  url,
  ip,
  ipv6,
  template,
}: ApprovedEmailProps) => (
  <Tailwind config={barebonesBoxedTailwindConfig}>
    <Html>
      <Head></Head>
      <Body className="bg-bg-2 m-0 text-center font-sans">
        <Preview>Confirm your email address</Preview>
        <Container className="mobile:mt-0 mx-auto mt-8 w-full max-w-[640px]">
          <Section>
            <Section className="bg-bg mobile:px-2 px-6 py-4">
              <Section className="mb-3 px-6">
                <Row>
                  <Column className="w-1/2 py-[7px] align-middle">
                    <Row>
                      <Column className="w-[32px] align-middle">
                        <Img
                          src="https://hackclub.app/nest.png"
                          alt="Nest Logo"
                          width={48}
                          className="block"
                        />
                      </Column>
                    </Row>
                  </Column>
                  <Column align="right" className="w-1/2 py-[7px] align-middle">
                    <Text className="font-13 m-0 text-right font-sans">
                      <span className="text-fg-3">Nest</span>
                    </Text>
                  </Column>
                </Row>
              </Section>

              <Section className="bg-bg-2 mobile:px-6 mobile:py-12 rounded-[8px] px-[40px] py-[64px] text-center">
                <Section className="mb-3">
                  <Heading as="h1" className="font-28 text-fg m-0 font-sans">
                    Nest account approved!
                  </Heading>
                </Section>

                <Text className="font-16 text-fg-2 mx-auto mt-0 mb-8 max-w-[380px] text-center font-sans">
                  Thank you for signing up for Nest.
                  <br />
                  To verify your account, we just need to confirm your email
                  address.
                </Text>

                <Section className="mb-6 text-center">
                  <Button
                    href={url}
                    className="bg-fg font-16 text-fg-inverted inline-block rounded-lg px-7 py-4 text-center font-sans leading-6"
                  >
                    Manage account
                  </Button>
                </Section>
              </Section>

              {/* Footer */}
              <Section className="bg-bg">
                <Row>
                  <Column className="px-6 py-10 text-center">
                    <Text className="font-13 text-fg-3 mx-auto mt-0 mb-8 max-w-[280px] text-center font-sans">
                      Barebones is the catchy slogan that perfectly encapsulates
                      the vision of our company.
                    </Text>
                    <Text className="font-11 text-fg-3 mt-4 mb-5 text-center font-sans">
                      {/* What should we put here honestly */}
                      123 Market Street, Floor 1
                      <br />
                      Tech City, CA, 94102
                    </Text>
                  </Column>
                </Row>
              </Section>
            </Section>
          </Section>
        </Container>
      </Body>
    </Html>
  </Tailwind>
);

ApprovedEmail.PreviewProps = {
  username: "Quetzal",
  url: "https://dashboard.hackclub.app",
} satisfies ApprovedEmailProps;

export default ApprovedEmail;
