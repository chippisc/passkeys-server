<?php

use Illuminate\Support\Facades\Event;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Events\LoggedInWithPasskey;
use Laravel\Passkeys\Passkeys;
use Laravel\Passkeys\Support\WebAuthn;
use Laravel\Passkeys\Tests\User;

afterEach(function (): void {
    Passkeys::authorizeLoginUsing(null);
});

it('does not log in when custom sign-in authorization callback returns false', function (): void {
    $user = User::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
    ]);

    $passkey = $user->passkeys()->create([
        'name' => 'My MacBook',
        'credential_id' => 'test-credential-id',
        'credential' => [],
    ]);

    $this->mock(VerifyPasskey::class)
        ->shouldReceive('__invoke')
        ->once()
        ->andReturn($passkey);

    Passkeys::authorizeLoginUsing(fn (): bool => false);

    $this->withSession(['passkey.verification_options' => WebAuthn::toJson(createRequestOptions())])
        ->postJson('/passkeys/login', ['credential' => createAssertionCredential()])
        ->assertUnprocessable();

    $this->assertGuest();
});

it('logs in when custom sign-in authorization callback returns true', function (): void {
    Event::fake();

    $user = User::create([
        'name' => 'Jane Doe',
        'email' => 'jane@example.com',
    ]);

    $passkey = $user->passkeys()->create([
        'name' => 'My iPhone',
        'credential_id' => 'test-credential-id-2',
        'credential' => [],
    ]);

    $this->mock(VerifyPasskey::class)
        ->shouldReceive('__invoke')
        ->once()
        ->andReturn($passkey);

    Passkeys::authorizeLoginUsing(fn (): bool => true);

    $this->withSession(['passkey.verification_options' => WebAuthn::toJson(createRequestOptions())])
        ->postJson('/passkeys/login', [
            'credential' => createAssertionCredential(),
            'remember' => true,
        ])
        ->assertOk()
        ->assertJsonStructure(['redirect'])
        ->assertJsonMissing(['verified']);

    $this->assertAuthenticatedAs($user);

    Event::assertDispatched(LoggedInWithPasskey::class, fn ($event): bool => $event->user->is($user) && $event->passkey->is($passkey));
});
