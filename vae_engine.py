import torch
import torch.nn as nn
import joblib
import numpy as np

# We redefine the exact architecture from the Kaggle Notebook
class VAE(nn.Module):
    def __init__(self, input_dim, latent_dim=16):
        super(VAE, self).__init__()
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU()
        )
        self.fc_mu = nn.Linear(32, latent_dim)
        self.fc_logvar = nn.Linear(32, latent_dim)
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim)
        )
        
    def encode(self, x):
        h = self.encoder(x)
        return self.fc_mu(h), self.fc_logvar(h)
    
    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def decode(self, z):
        return self.decoder(z)
    
    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        return self.decode(z), mu, logvar

class VAEDetector:
    def __init__(self, model_path='vae_full_model.pth', scaler_path='scaler.pkl', threshold=0.5):
        self.device = torch.device('cpu') # Inference runs instantly on CPU
        
        print("Loading Scaler...")
        self.scaler = joblib.load(scaler_path)
        
        print("Loading PyTorch VAE Weights...")
        state_dict = torch.load(model_path, map_location=self.device)
        
        # Dynamically determine the input_dim from the saved weights
        self.input_dim = state_dict['encoder.0.weight'].shape[1]
        print(f"Detected {self.input_dim} numeric flow features.")
        
        self.model = VAE(self.input_dim, latent_dim=16).to(self.device)
        self.model.load_state_dict(state_dict)
        self.model.eval()
        
        self.threshold = threshold

    def predict(self, features_array):
        """
        Calculates the Reconstruction Error (MSE) for a given network flow.
        """
        # 1. Scale the raw features using the exact scaler from training
        features_scaled = self.scaler.transform([features_array])
        
        # 2. Convert to PyTorch Tensor
        tensor_data = torch.FloatTensor(features_scaled).to(self.device)
        
        # 3. Pass through the Autoencoder
        with torch.no_grad():
            recon_batch, _, _ = self.model(tensor_data)
            mse = torch.mean((recon_batch - tensor_data) ** 2).item()
            
        is_anomaly = mse >= self.threshold
        return mse, is_anomaly
