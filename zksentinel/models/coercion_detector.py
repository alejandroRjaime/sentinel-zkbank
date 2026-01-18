"""
============================================
ZK-Sentinel: Coercion Detection Model (ZKML)
============================================

LSTM model that detects coercion from behavioral biometrics.
Designed to be converted to ZK circuit via EZKL.

Input features:
- Typing speed (chars/second)
- Keystroke interval variance
- Error/correction rate
- Response time to prompts
- Time of day (normalized)
- Deviation from historical patterns

Output: coercion probability (0-1)
"""

import torch
import torch.nn as nn
import numpy as np
from pathlib import Path


class CoercionDetector(nn.Module):
    """
    LSTM-based coercion detector.
    Small model optimized for ZK circuit conversion.
    """
    
    def __init__(self, input_size=10, hidden_size=32, num_layers=2):
        super().__init__()
        
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0
        )
        
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        """
        Args:
            x: (batch, seq_len, input_size) - sequence of biometric features
        
        Returns:
            (batch, 1) - coercion probability
        """
        lstm_out, _ = self.lstm(x)
        last_hidden = lstm_out[:, -1, :]  # Take last timestep
        return self.classifier(last_hidden)


class SimplifiedDetector(nn.Module):
    """
    Simplified MLP version for smaller ZK circuits.
    ~5K constraints vs ~40K for LSTM.
    """
    
    def __init__(self, input_size=10):
        super().__init__()
        
        self.layers = nn.Sequential(
            nn.Linear(input_size, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        """
        Args:
            x: (batch, input_size) - biometric features
        
        Returns:
            (batch, 1) - coercion probability
        """
        return self.layers(x)


def generate_synthetic_data(n_samples=10000, seq_len=10, n_features=10):
    """
    Generate synthetic training data.
    
    Normal behavior: Consistent patterns
    Coerced behavior: High variance, unusual timing, errors
    """
    X = []
    y = []
    
    for _ in range(n_samples):
        is_coerced = np.random.random() < 0.3  # 30% coerced samples
        
        if is_coerced:
            # Coerced: High variance, unusual values
            seq = np.random.randn(seq_len, n_features) * 2  # Higher variance
            seq[:, 0] *= 0.5  # Slower typing
            seq[:, 1] *= 2    # Higher keystroke variance
            seq[:, 2] += 1    # More errors
        else:
            # Normal: Consistent, predictable
            seq = np.random.randn(seq_len, n_features) * 0.5
        
        X.append(seq)
        y.append(1 if is_coerced else 0)
    
    return torch.tensor(np.array(X), dtype=torch.float32), \
           torch.tensor(np.array(y), dtype=torch.float32).unsqueeze(1)


def train_model(model, X_train, y_train, epochs=100, lr=0.001):
    """Train the coercion detector."""
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    
    model.train()
    for epoch in range(epochs):
        optimizer.zero_grad()
        outputs = model(X_train)
        loss = criterion(outputs, y_train)
        loss.backward()
        optimizer.step()
        
        if (epoch + 1) % 20 == 0:
            accuracy = ((outputs > 0.5) == y_train).float().mean()
            print(f"Epoch {epoch+1}/{epochs}, Loss: {loss.item():.4f}, Acc: {accuracy:.4f}")
    
    return model


def export_to_onnx(model, output_path, input_shape):
    """Export model to ONNX format for EZKL conversion."""
    model.eval()
    dummy_input = torch.randn(*input_shape)
    
    torch.onnx.export(
        model,
        dummy_input,
        output_path,
        export_params=True,
        opset_version=11,
        do_constant_folding=True,
        input_names=['input'],
        output_names=['output'],
        dynamic_axes={
            'input': {0: 'batch_size'},
            'output': {0: 'batch_size'}
        }
    )
    print(f"Model exported to {output_path}")


def main():
    # Create models directory
    Path("../build").mkdir(exist_ok=True)
    
    print("=== Training LSTM Coercion Detector ===")
    
    # Generate data
    X_train, y_train = generate_synthetic_data(n_samples=5000)
    print(f"Training data shape: {X_train.shape}")
    
    # Train LSTM model
    lstm_model = CoercionDetector(input_size=10, hidden_size=32, num_layers=2)
    lstm_model = train_model(lstm_model, X_train, y_train, epochs=100)
    
    # Save PyTorch model
    torch.save(lstm_model.state_dict(), "../build/coercion_lstm.pt")
    print("Saved: build/coercion_lstm.pt")
    
    # Export to ONNX
    export_to_onnx(lstm_model, "../build/coercion_lstm.onnx", (1, 10, 10))
    
    print("\n=== Training Simplified MLP ===")
    
    # Train simplified model (for smaller ZK circuits)
    X_simple = X_train[:, -1, :]  # Use only last timestep
    simple_model = SimplifiedDetector(input_size=10)
    simple_model = train_model(simple_model, X_simple, y_train, epochs=100)
    
    # Save and export
    torch.save(simple_model.state_dict(), "../build/coercion_mlp.pt")
    export_to_onnx(simple_model, "../build/coercion_mlp.onnx", (1, 10))
    
    print("\n=== Complete ===")
    print("Models ready for EZKL conversion:")
    print("  - build/coercion_lstm.onnx (full LSTM)")
    print("  - build/coercion_mlp.onnx (simplified MLP)")


if __name__ == "__main__":
    main()
